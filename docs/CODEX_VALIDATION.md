## R2 macOS protected R1-to-R3 issuer increment (2026-10-31)

Source/CTest authored against parent `7032eef4d41c9c224be9a99aa2d19424746a1842` via GitHub connector.
Canonical local configure/build/full/focused CTest and ASan/UBSan: NOT RUN
(no approved `~/rdp-server/` checkout; container DNS cannot reach GitHub).
Publication-SHA hosted CI: PENDING. No real macOS native lease, physical
RDP client, Share, graphics, input or clipboard claim. Next R2 increment:
protect Attach/joins/Client Info/PersonalDesktop licensing/Share/Graphics
plus production-backed real TLS completion/post-callback retirement fixture.

## R3 macOS post-Attach/Join revocation regression (2026-10-31)

- Source review on parent `0f87e435e9bef42d3b55b7d0c53dcd5bd29f4202`: R3's positive methods remain private
  to the existing concrete R2 brokers and test friend. No production R3
  primitive or additional friend is necessary for Agent 2's handoff.
- Added distinct ordinary production-backed `transport.mcs-macos-post-attach-join-revocation-denials`,
  reusing `test_macos_r2_mcs_gateway` and the R3 lifecycle (no native lease).
  The earlier macOS private-entry generation-denial CTest and the fixed
  171-case MCS table are unchanged.
- No checkout/build root is available in this GitHub connector environment
  (direct GitHub DNS resolution fails). Canonical local Debug configure/build,
  focused/full CTest, ASan/UBSan: **NOT RUN**. Exact-publication-SHA hosted CI:
  **PENDING**. No live desktop/client/clipboard tests were authorized.
- Agent 2 must separately implement and qualify the actual protected R1/R3
  issuer and post-callback authority-loss retirement before R10 composition.

## R7 QColorSpace full-CTest interpreter-order correction (2026-10-31)

The full Debug protocol jobs at ancestor `2f7ee6d033700c7a6bbfa51387de9835bf974358`
reached **801 macOS** and **1023 Ubuntu** CTests. Their only non-skipped
failure was `macos.gui-qcolor-provenance-parser-and-redaction` **NOT RUN**:
the CTest executable field was empty because R7 registered the test before
`find_package(Python3 REQUIRED COMPONENTS Interpreter)`.
The same test is now registered after existing Python discovery, with a
configure-time denial for an empty interpreter. No native/Qt/R4 change.
**Exact-head qualification:** `0f87e435e9bef42d3b55b7d0c53dcd5bd29f4202`,
Actions `41179872107`, hosted full Ubuntu Debug **1024/1024 PASS**,
macOS Debug **802/802 PASS**, Windows Debug **848/848 PASS**. The repaired
`macos.gui-qcolor-provenance-parser-and-redaction` CTest individually
**PASSes Debug and Release on all three** (Ubuntu #165, macOS #118,
Windows #119). The macOS portable GUI selection also PASSes
`gui.offscreen-qcolor-valid-and-malformed-metadata`. R7 macOS native
lifecycle **22/22 Debug and Release PASS**, including the existing
`macos.native-desktop-owner-borrow-callback-retirement`; macOS portable
GUI, R7 sanitizers, GUI parity and separate structure `41179872115`
**PASS**. Empty-interpreter configure denial is source-verified; its
missing-interpreter negative configuration was not separately injected.
The optional clean-Windows packaged job remained queued at inspection and
is not counted as PASS.

**Diagnostic-only next increment:** the original offline Python fixture
gains invalid ICC `acsp` signature, length/truncation, false Cocoa-plugin
lookup and Windows-path/oversized-line redaction denials. No Qt production
conversion, native capture/input, CMake registry or listener changes.
New publication-SHA CTest/hosted CI: **PENDING**; local canonical
build/CTest **NOT RUN**. The owner's packaged no-Sharing Cocoa warning
caller is **UNATTRIBUTED / NOT RUN**. R2 prepared authorization, private
R3 entry and synthetic R10 CredSSP still do not constitute positive
R10-assembled native Admission/Share/GraphicsReady attachment.

## R1 macOS concrete private access and prepared-only denial (2026-10-31)

- Agent 2's `MacConsoleAdmissionBroker` and Agent 3's private R3 friend edge
  are now on current `main`. The R1 increment adds only that same concrete
  R2 class as a private friend of `OwnedPreauthTcpConnection` and preserves
  every existing TLS/connection/admission check. No method becomes public.
- New `security.native-authorization-macos-console-prepared-transport-dormancy`
  reuses the existing production R1/R2 executable and asserts that preparation,
  protected R2 visit and listener-replacement retirement never promote an
  inactive accepted connection to first-MCS. It fabricates no native lease.
- Local canonical configure/build/focused/full CTest and sanitizers: **NOT RUN**
  (GitHub connector environment lacks the approved checkout; direct clone DNS
  resolution is unavailable). Source/CTest registration: **PASS by inspection**.
  Exact-publication-SHA hosted CI: **PENDING**; physical clients and native
  admission: **NOT RUN / unauthorized**.
- Focused R1 follow-up source audit on `main` parent `00da1aa56fc29c7235e7caa95ccde415fda90d42`:
  `OwnedPreauthTcpConnection::completeCredSspAdmission()` checks the live
  SSL/BIO, absence of pending TLS application I/O and the exact pinned
  HYBRID-selected certificate before its single transport-stage transition.
  Duplicate completion and wrong/closed stage fail terminally. R1 transport
  success alone does not publish an R2 lease or consume first-MCS plaintext;
  macOS R10 remains explicitly pre-MCS after CredentialsVerified. The Linux
  runtime already cancels R1 after broker admission failure and revalidates R2
  before every first-MCS read. `cancel()` retires adapter state and SSL/BIO
  before invalidating/closing the socket; a reused descriptor cannot be
  double-closed by this owner. Existing negative tests cover no admission,
  certificate/transport replacement, TLS WANT, buffered data, FIN, RST and
  close_notify. **PASS by source/registration inspection only.** No R1
  production change or new CTest is justified before Agent 2's positive
  macOS broker implementation. Canonical local build/full CTest/sanitizers:
  **NOT RUN** (no cloneable approved checkout); publication-SHA hosted CI:
  **PENDING**; physical client: **NOT RUN / unauthorized**.
- Agent 2's protected-completion contract: complete R1 exactly once within
  fresh, generation-bound native authorization; revalidate original proof,
  consent epoch, R1 identity and native evidence after any synchronous
  callback. The R1 stage change is transport-only; R2 lease publication
  after this check is the admission linearization point. On lost authority,
  close R3/proof/framing and `connection.cancel()` synchronously before
  any buffered MCS bytes are read. Only an active R2 lease may authorize
  first-MCS intake and the separate R3 private generation binding. Agent 2
  must add a production-linked positive/post-callback-revocation regression.

## R8 callback-time source fence — exact descendant sanitizer qualification (2026-10-31)

- Published R8 production/test/docs correction: `bd68b5a063bf33d993854f22f4ff3c8da255a59c`.
- Exact qualifying descendant: `2f7ee6d033700c7a6bbfa51387de9835bf974358`,
  GitHub Actions run `41179113155`, `r9-security-protocol-sanitizers` job
  `124472700546`: **PASS**. Reviewed decoded job logs, not just workflow status.
- Fixed clipboard labeled selector: **107/107 PASS**. Separate combined
  native file-finalization CTest: **1/1 PASS**. New production-backed
  `clipboard.x11-native-callback-source-retirement`: **1/1 PASS**.
  Separately pinned R3 static CLIPRDR route tests: **9/9 PASS**.
- The new R8 behavior is outside the 107-case `clipboard` label census.
  No source/CTest/census adjustment is required and no live clipboard is enabled.
- Ubuntu/macOS/Windows Debug compilation: **PASS** on this descendant.
  Full Debug CTest is **not green**, solely due to unrelated
  `macos.gui-qcolor-provenance-parser-and-redaction` **Not Run**:
  `tests/CMakeLists.txt` registers it at line 111 with
  `${Python3_EXECUTABLE}` before its `find_package(Python3 REQUIRED
  COMPONENTS Interpreter)` at line 1328; CTest reports an empty executable.
  This is R7 test-registration ownership, not an R8 failure.
- R4's earlier fixed-array compile failure is resolved on this descendant:
  the 171-case table remains intact and the independent R4 behavior is
  dispatched separately. No R8 changes were needed for that repair.
- Future R10 positive native integration is still blocked by the deliberate
  `kLinuxProductionClipboardActivationApproved = false` gate and the
  prerequisite of a genuinely current R2 clipboard lease, activated Share,
  current joined `cliprdr`, GraphicsReady, one native clipboard owner, sole R1
  writer and exact bounded write receipts. Synthetic tests confer no authority.
- Physical RDP clients, local clipboard, native file creation, browser paste
  and file-manager operations remain **NOT RUN / unauthorized**.

## R3 macOS private protocol edge exact-SHA hosted receipt (2026-10-30)

Corrective descendant `4f1a5931c75daa468996b6a0d6465de197772b21`,
primary Actions `41178462215`, preserves R3 implementation
`2a45d7c54c025f21623775d539eb5f107ad08ae5` and aligns the new CTest on the
durable name `transport.mcs-macos-private-admission-generation-denials`.
The dedicated production-linked test compiles and **PASSes** on all three
hosted protocol toolchains: Ubuntu/GCC job `124470806328`, test 357/1023
**PASS (0.00 s)**; macOS/Clang job `124470806387`, test 311/801
**PASS (0.01 s)**; Windows/MSVC job `124470806360`, test 312/847
**PASS (0.02 s)**. R9 security/protocol ASan+UBSan job `124470806274`
**PASS**. Structure, documentation policy, both R2 Linux production-security
lanes, macOS session sanitizers, GUI parity and bootstrap gates on the same SHA
also **PASS**.

The repository-wide Ubuntu, macOS and Windows protocol jobs are not aggregate
PASSes: each reaches ordinary CTest and is blocked only by unrelated
`macos.gui-qcolor-provenance-parser-and-redaction` **NOT RUN** because its
CTest command captured an empty Python executable before the later
`find_package(Python3 ...)`. The R3 gate itself built and passed before that
failure. Canonical owner-local build/full CTest and benchmark remain **NOT
RUN**; physical macOS admission/client tests remain **NOT RUN / unauthorized**.

**Agent-2 protected R3 handoff.** `MacConsoleAdmissionBroker` is the only new
production friend. Its first positive call is
`onVerifiedR2ConnectInitial(admissionGeneration_, prepared_.authorizationGeneration, ...)`.
Before every later call below, R2 must first
`revokeUnlessAdmissionBindingMatches(admissionGeneration_,
prepared_.authorizationGeneration)`, perform its fresh proof/R1/native/owner
checks, and after any callback revalidate the protected native visitor before
reporting success to R10:

- Connect Response: `prepareConnectResponseWrite`,
  `completeConnectResponseWrite`; Erect/Attach:
  `onVerifiedR2ErectDomain`, `onVerifiedR2AttachUser`,
  `prepareAttachUserConfirmWrite`, `completeAttachUserConfirmWrite`.
- Joins/Client Info: `onVerifiedR2ChannelJoin`,
  `prepareChannelJoinConfirmWrite`, `completeChannelJoinConfirmWrite`,
  `resolveVerifiedR2JoinedClipboardChannel`,
  `acceptVerifiedR2ClientInfoPacket`.
- PersonalDesktop licensing: `selectVerifiedR2PersonalDesktopLicensingMode`,
  `prepareServerLicenseRequestWrite`, `completeServerLicenseRequestWrite`,
  `acceptVerifiedR2ClientLicensingMessage`,
  `preparePersonalDesktopValidClientWrite`,
  `completePersonalDesktopValidClientWrite`.
- Activation: `prepareVerifiedR2MacDemandActiveProfile`,
  `beginVerifiedR2ShareActivation`,
  `pendingVerifiedR2ShareActivationWrite`,
  `completeVerifiedR2ShareActivationWrite`,
  `acceptVerifiedR2ShareActivationPdu`,
  `verifiedR2ApplicationTrafficReady`.
- Post-Share: `classifyVerifiedR2PostShareTpkt`,
  `resolveVerifiedR2ActivatedClipboardChannel`,
  `acceptVerifiedR2ClipboardTpkt`, `queueVerifiedR2ClipboardPdu`,
  `pendingVerifiedR2ClipboardWrite`, `completeVerifiedR2ClipboardWrite`,
  `routeVerifiedR2SlowPathInputPdu`,
  `resolveVerifiedR2ActivatedDynamicVirtualChannel`.
- Graphics: `beginVerifiedR2GraphicsDynamicVirtualChannel`,
  `pendingVerifiedR2GraphicsDynamicVirtualChannelWrite`,
  `completeVerifiedR2GraphicsDynamicVirtualChannelWrite`,
  `acceptVerifiedR2GraphicsDynamicVirtualChannelPdu`,
  `consumeVerifiedR2GraphicsFrameAcknowledge`,
  `preflightVerifiedR2GraphicsFramePublication`,
  `beginVerifiedR2GraphicsSurfaceReconfiguration`,
  `beginVerifiedR2GraphicsClearCodecFramePublication`,
  `cancelVerifiedR2UnwrittenGraphicsFrame`,
  `abortVerifiedR2GraphicsFrame`.

Every prepare/retry/completion and every accepted-byte receipt remains inside
the same R2 generation pair. Zero-byte or partial progress does not confer a
new capability. R2 revocation/replacement closes R3 before a later receipt can
advance and thereby retires joins, licensing, Share, routes and graphics
credit. R10 receives neither these private methods nor generation scalars.

## R10 completed macOS CredSSP exact-SHA hosted receipt (2026-10-30)

- Implementation commit: `96b9e8ccee1eb5f13499f2a50e7ca5a573319063`.
  Its own aggregate CI was blocked by a concurrent stale R3 MCS table cardinality
  before the macOS regression could qualify.
- Unchanged-test descendant:
  `4f1a5931c75daa468996b6a0d6465de197772b21`, primary Actions
  `41178462215`, macOS protocol job `124470806387`.
  Debug configure and compile **PASS**. Ordinary full Debug CTest executed the
  production-backed
  `runtime.macos-host-control-completed-credssp-without-native-admission-denials`
  as test 73/801 and it **PASS (0.69 s)** after real X.224 HYBRID/TLS/direct-NTLM
  CredSSP, final `authInfo` / `CredentialsVerified`, queued checked-in
  Microsoft Connect-Initial, pre-MCS dormancy and the Stop/consent/session
  retirement scenarios.
- The same macOS full Debug CTest is **BLOCKED at 800/801** by unrelated R7
  `macos.gui-qcolor-provenance-parser-and-redaction` **NOT RUN**. CTest reports
  an empty executable; source inspection shows that test uses
  `${Python3_EXECUTABLE}` at `tests/CMakeLists.txt:112` before the existing
  `find_package(Python3 REQUIRED COMPONENTS Interpreter)` at line 1328.
  Release is therefore **NOT RUN** in that job. Ubuntu full CTest is blocked by
  the same registration defect. R9 security/protocol sanitizers, structure,
  documentation policy and R2 production-security jobs on this descendant are
  independently **PASS**.
- This receipt proves **authenticated = yes** for the synthetic standalone
  credential path and **admitted = no / ShareActivated = no /
  native-attached = no**. It is not physical-client or native OS admission
  evidence.
- Agent 3's private macOS R3 edge is present on this descendant, but Agent 2's
  current `MacConsoleAdmissionBroker` still exposes only
  `prepareAdmission/revalidate/visitNativeAuthorization/revoke` and no
  protected R3 transition. R10 therefore still cannot legally compose the
  positive pipeline without violating the issuer boundary.

## R10/R3 macOS gateway registration alignment (2026-10-30)

R3 publication `2a45d7c54c025f21623775d539eb5f107ad08ae5`
failed at configure because its new CTest name contained internal `r2`
ownership taxonomy. First repair `cded647a1925d675dc9d1da39f216c3ce6509281`
changed the `set_tests_properties` target only; the
`add_rdp_test(test_macos_r2_mcs_gateway.cpp ...)` registration still created
the prohibited old name. This correction changes only that registration suffix
to `mcs-macos-private-admission-generation-denials`, exactly matching the already-documented durable CTest
name. No production R2/R3 behavior, assertions, fixed 171-case MCS dispatch,
Linux runtime path, or R10 HostControl state changes. Canonical local
build/CTest is **NOT RUN** in this connector environment; corrective
publication-SHA hosted CI is **PENDING**.

## R3 macOS concrete R2 private entry authoring (2026-10-30)

- Reconciled authoring parent: `de2c6f79b851a0aabe0ab9dafb13aa13a2e55189`, including Agent 2's concrete
  `MacConsoleAdmissionBroker` and R10's completed-CredSSP pre-admission
  denial coverage; no active M1 publication freeze was present.
- R3 friends exactly that concrete R2 issuer, never R10 or a native-view/generic
  callback. Public MCS Connect-Initial stays denial-only.
- Generation contract: R3 admission generation =
  `MacConsoleAdmissionBroker::admissionGeneration_`; R3 session generation =
  the broker's captured `prepared_.authorizationGeneration`. Every later
  transition/write/receipt must revalidate that pair before fresh protected R2
  checks; callback-time authority loss must revoke R3 before success escapes.
- Audited private path covers Connect-Response, Erect, Attach/Confirm, joins,
  Client Info, PersonalDesktop licensing/Valid Client, macOS Demand/Confirm
  Active, Share, post-Share classifier, CLIPRDR, slow-path input and Graphics
  DVC/ACK/frame publication.
- Dedicated offline CTest covers public denial, zero/partial write receipt
  continuity, wrong-generation completion and stale-generation next-MCS denial
  without fabricating native proof.
- Concurrent R4 work had added a 172nd initializer to
  `std::array<McsTestCase, 171>`. Preserve the R4 CTest/all-cases execution but
  dispatch that case outside the fixed 171-entry table.
- MS-RDPBCGR review preserved Connect-Response/Erect/Attach/Join ordering,
  Enhanced Security separation, user-channel 1001..65536, and macOS General
  Capability OSMAJORTYPE_OSX/unspecified-minor identity.
- Source/registry review: PASS by inspection. Local canonical build/full CTest,
  sanitizers and benchmark: NOT RUN in this connector environment. Hosted exact
  publication-SHA CI: PENDING. Physical native admission/client testing:
  NOT RUN / unauthorized.

## R6 paired Microsoft interop/evidence qualification — 2026-10-30

**Authoring parent:** `96b9e8ccee1eb5f13499f2a50e7ca5a573319063`. No new physical or hosted R6 qualification
is claimed for this head.

Downloaded artifact 13029796352,
`r9-microsoft-interop-c88dc60f9e218797ddcd640af6bba1693adca1d7`,
digest
`sha256:65b3d87c269111d6a6f3b5e44dca63d083dbeefe8332c25e313ec7fbfe15a428`.
Its embedded result is exact-source `c88dc60f...` and ends
`interop-matrix-final=COMPLETE_PASS`: fixed/IP NTLM, OEM differential,
credential semantic controls, required-AV negatives, full production CredSSP,
mismatched binding, and fixed/IP-SPN/bare-IP target rows pass. Full exchange
separately records `authinfo=yes`, `credentials-verified=yes`,
`production-authinfo-empty-fields=none`, `delegation-returned=no` and
`native-admission=no`; delegation neither negates nonempty authInfo nor
creates an R2 lease. This is ancestor exact-SHA evidence, not current-head
qualification.

Paired schema v2 binds supplemental facts to exact
SHA/certificate/destination/service-endpoint/attempt/connection/terminal/window
provenance and independently records client Type2-received, CredSSP-accepted,
Type3-generated and Type3-delivered observations. Offline negatives reject
mixed attempt IDs, fingerprints, credential controls, targets and windows; a
positive case proves client-side Type3 delivery does not manufacture
server-side Type3 receipt.

Existing `windows.capture-session-change-callback-revocation` and
`windows.sendinput-authority-retirement-no-native-post` already cover
authority loss during in-flight DXGI map/SendInput with terminal retirement and
no post-revocation native input; no duplicate native regression is warranted.

The current owner record (about 68 ms Type-2-to-FIN, zero post-Type-2 server
bytes) remains distinct from the earlier roughly 9.5 ms attempt with a
different certificate fingerprint. Neither proves client Type2 receipt,
CredSSP acceptance or Type3 generation/delivery. Physical A/B remains
**BLOCKED / NOT RUN** pending exact-SHA R9 candidate PASS and separate owner
authorization. Canonical build/full CTest and publication-SHA hosted CI for
this increment are **NOT RUN / PENDING** at authoring.

## R10 completed macOS CredSSP pre-MCS denial authoring (2026-10-30)

- Initial authoring base: `b76f62917479ff3a1e512d7c6c791157d97d2f2c`.
  Concurrent main advanced through R8/R9, Agent 2's macOS admission-preparation
  commit and the R7 QColorSpace fixture correction; the atomic increment was
  reconciled onto `c2be669ed8044ef4188d13279d5a6e535da1e769` without
  overwriting those changes. The canonical roadmap still records no nominated
  M1 publication freeze.
- Added one distinct production-backed macOS HostControl behavior:
  `runtime.macos-host-control-completed-credssp-without-native-admission-denials`.
  Its synthetic local peer uses real X.224 HYBRID, R1 TLS and standalone
  direct-NTLM CredSSP through final `authInfo` / `CredentialsVerified`,
  then queues the checked-in Microsoft 416-byte Connect-Initial. The server
  remains pre-MCS and proves no Share, graphics, native attachment or clipboard.
- Retirement coverage after completed CredSSP includes Stop, same-permission
  owner-consent epoch replacement and native session replacement. Stop is also
  the production barrier before credential replacement; the replacement
  generation cannot be visited through the retired generation.
- R2/R3 integration audit: Agent 2's new `MacConsoleAdmissionBroker` is a real
  R2-owned preparation gateway bound to the exact proof/R1 connection, but its
  contract explicitly says `Prepared` is not an R1/R3 admitted state.
  `McsSessionLifecycle` is unchanged and still exposes no macOS private
  positive route. R10 therefore does not call `completeCredSspAdmission()`,
  become an R3 friend, fabricate admission generations or attach R7. Positive
  macOS MCS/Share remains BLOCKED on Agent 3's private R3 route plus the R2
  protected transition that consumes it.
- Linux source-level review: the existing direct-NTLM lifecycle remains the
  behavioral oracle for the synthetic peer; no Linux runtime source or API is
  changed by this increment.
- Canonical local `~/rdp-server/build` configure/build/focused/full CTest:
  **NOT RUN** in this connector environment because the approved owner checkout
  is unavailable and direct GitHub clone DNS resolution failed. Benchmark:
  **NOT RUN / not applicable** to this denial-only test increment. Exact
  publication-SHA hosted macOS/full/R9 qualification: **PENDING** until the
  atomic direct-main publication exists. Physical client/native desktop:
  **NOT RUN / unauthorized**.

## R2 concrete macOS admission gateway first round — 2026-10-30

- Reconciled parent: `bd68b5a063bf33d993854f22f4ff3c8da255a59c`.
  Concurrent direct-main R3/R5/R7/R8/R9 work was preserved; it did not alter
  the R1/R3 private friend boundaries or R2 production sources consumed here.
- Added the noninstalled cross-platform
  `rdp-server-mac-console-admission` target and production
  `MacConsoleAdmissionBroker`. The broker owns one prepared
  `MacNativeDesktopAuthorization`, requires a proof that privately matches the
  exact accepted R1 connection and configured credential generation, snapshots
  the original authorization/native lifetime only through a protected visitor,
  and rechecks proof/connection before and after every downstream native borrow.
- Added eight behavior-named offline CTests in the existing
  `test_native_desktop_standalone_authorization` executable: stale proof,
  wrong connection, permission scope, same-permission consent replacement,
  nested reentry, native session replacement, post-callback authority loss and
  explicit listener-replacement retirement. No physical macOS lease, TCC,
  listener, R3 session, capture/input or clipboard is created by these fixtures.
- R1 `completeCredSspAdmission()` and R3 verified-R2 methods remain private to
  the Linux broker at this parent. The agreed concrete future friend type is
  `rdp_server::server::security::MacConsoleAdmissionBroker`; this first round
  intentionally changes neither private owner.
- Source/registration review: **PASS by inspection**. Local configure/build/CTest
  and sanitizers: **NOT RUN** (no approved canonical checkout in this connector
  environment). Exact-publication-SHA hosted CI: **PENDING**. Physical
  client/native acceptance: **NOT RUN / unauthorized**.

## R8 clipboard authority/finalization audit — X11 callback source fence (2026-10-30)

- Authoring parent: `67f11aafb7825bb02e55084bd29415164ac7bccc`; concurrent R4/R5/R7 work is retained.
- **R3/R2 route audit PASS by inspection:** every R8 bridge dispatch/queue is
  preceded by the protected current-route visit; route generation, reply/slice
  receipts and local source generation invalidate stale observations. No
  Clipboard Enabled projection was found; Linux production activation remains
  `kLinuxProductionClipboardActivationApproved = false`.
- **Distinct gap found:** X11 native owner/property callbacks could synchronously
  retire and replace `RemoteTransfer` while reusing the same numeric clipboard
  generation. The adapter could then commit native ownership, emit direct
  property success or retain/advance an INCR span for the retired source epoch.
- Correction revalidates generation + monotonic source epoch + X11 ownership
  epoch after owner/property callbacks, withdraws stale properties/ownership,
  restores INCR event masks and never advances stale INCR progress.
- New ordinary production-backed CTest:
  `clipboard.x11-native-callback-source-retirement`. It is intentionally
  outside the fixed clipboard label census and is executed separately under the
  existing sanitizer build. The inherited `b76f629...` baseline remains
  **107/107 clipboard + 1/1 combined native finalization PASS**; this publication
  must revalidate those unchanged selectors plus the new exact-name test.
- macOS/Windows write/resize/flush/close callback fences are unchanged. Linux
  file materialization remains direct thread-affine `pwrite`/resize/fsync/close
  with exact source checks; no injected-callback assumption was added.
- FileContents audit retained the 64 KiB RANGE ceiling, checked offset/size
  arithmetic, monotonic nonrecycled stream/receipt identities, metadata-only
  FILEDESCRIPTORW names/hierarchy, cancellation and caller-selected local path
  ownership. Remote names still grant no filesystem path authority.
- Local canonical configure/build/full CTest, ASan/UBSan and benchmark:
  **NOT RUN** in this connector environment. Exact-publication-SHA hosted
  structure/full/sanitizer: **PENDING**. Live clipboard, file creation, browser
  paste, file manager and physical clients: **NOT RUN / unauthorized**.

## R5 Linux/X11 generation-safety and producer-provenance re-audit (2026-10-30)

- Authoring parent: `4a6594e29fd2554a2032d5721180782521390090`. Source audit **PASS by inspection**: R10 performs fresh R2 application-traffic authorization before X11 event service and again before input/frame work; R2 revalidation includes the exact prepared owner-consent epoch; per-event input dispatch reauthorizes immediately before the native sink; R5 post-callback capture/geometry checks remain intact. No production X11 change is justified.
- Existing production-backed Xvfb coverage already exercises queued/reentrant XDamage, RandR/same-pixel generation turnover, same-session-generation replacement owners, in-flight XShm retirement, graceful held-input release and terminal no-post XTEST retirement. Keep the native sanitizer inventory exactly **45**.
- Found validator-only gap: private schema v1 could not prove that otherwise consistent Admission/Share/frame/ACK scalars came from one producer-correlated attempt. Private schema v2 adds same-attempt IDs for observed credential/admission/Share/frame/ACK/input/RandR evidence, the fixed `linux-console-admission-broker` Admission producer class, and a distinct reconnect attempt ID. The redacted public schema remains unchanged and contains no attempt IDs.
- Focused offline CTest `linux.x11-owner-private-evidence-attempt-provenance-denials` uses the existing Python validator test executable and is outside the native X11 sanitizer selector; no internal R5 label, listener, desktop, XTEST or credential use.
- Repository evidence records only an owner-local **1060/1060** summary with SHA/toolchain/configuration/command missing. No 1066/1066 exact-SHA receipt was found. M1 owner Linux evidence remains **UNPINNED / NOT VERIFIED**.
- Isolated exact proposed Python blobs: syntax compile **PASS**, full validator unittest **18/18 PASS**, focused same-attempt provenance unittest **1/1 PASS**. Connector-local canonical CMake build/CTest and ASan/UBSan: **NOT RUN**. Exact publication-SHA hosted full/focused CTest and unchanged 45/45 native sanitizer selection: **PENDING**. Physical seat0/client/capture/input: **NOT RUN / unauthorized**. Benchmark: **NOT RUN**.

## R7 QColorSpace owner-provenance diagnostic artifact (2026-10-30)

- Reconciled authoring parent: `fd612d0a0c80d5582934b44ab39a2310294b507c`.
  First-party Qt production remains free of `QColorSpace`, `QImage` and
  `QPixmap` construction. The only Qt GUI image request found is the standard
  `QStyle::SP_ComputerIcon`; ScreenCaptureKit remains explicit 32-bit BGRA,
  native display observation is geometry-only, and the native cursor path uses
  CoreGraphics `CGColorSpaceCreateDeviceRGB` without Qt/ICC translation.
- Added opt-in `scripts/diagnose_macos_qcolor_provenance.py`. It launches only
  the exact extracted zero-argument Cocoa executable, verifies no TCP listener,
  retains at most 256 KiB of private Qt stderr in memory, and emits a redacted
  summary containing bundled Qt versions, Cocoa-plugin observation, display
  color model, ICC device-class signature and first matching warning source
  basename/line/category. It never prints ICC payloads, primaries or host paths,
  including path-bearing native/subprocess exception text, and never starts
  Sharing, capture or input.
- Added offline `macos.gui-qcolor-provenance-parser-and-redaction` for ICC
  header bounds, environment isolation and output redaction, plus
  `gui.offscreen-qcolor-valid-and-malformed-metadata` in the existing Qt
  harness for valid sRGB/custom primaries, a malformed ICC blob and an invalid
  chromaticity with `x + y > 1`. The synthetic malformed case can exercise
  Qt's validation boundary but cannot attribute the owner's Cocoa warning.
- Initial exact-SHA GUI evidence at `4a6594e29fd2554a2032d5721180782521390090`
  compiled `test_desktop_gui_offline` with Apple Clang 21.0.0, then
  `gui.offscreen-qcolor-valid-and-malformed-metadata` **FAILED** because the
  attempted duplicate red/green negative remained valid in Qt 6.12. Qt's
  chromaticity sanity rule validates each point independently.
- Corrective exact SHA `c2be669ed8044ef4188d13279d5a6e535da1e769`,
  Actions run `41177821199`, job `124468954004`: arm64 macOS, Qt **6.12.0**,
  Apple Clang **21.0.0 (clang-2100.1.1.101)**. Real
  `rdp-server-desktop.app` compilation **PASS**; portable-GUI integrity
  **3/3 PASS**; complete `gui.offscreen-*` batch **53/53 PASS**, including
  `gui.offscreen-qcolor-valid-and-malformed-metadata` **PASS (0.04 s)**,
  credential guidance, Advanced security/authentication redaction, empty
  Session Password default and listener-readiness gates. The same extracted
  archive's canonical zero-argument Cocoa LaunchServices smoke **PASS** with
  no TCP listener. No Sharing, TCC, capture, input or physical client ran.
- Same corrective SHA, job `124468954030`: focused R7 native lifecycle
  Debug **22/22 PASS** and Release **22/22 PASS** with Apple Clang 21.0.0;
  `macos.native-desktop-owner-borrow-callback-retirement` **PASS (0.02 s)**
  in both configurations. It remains the single FrameMailbox
  reentrant-retirement regression and is not duplicated.
- The repository-wide macOS protocol job at the corrective SHA still stops
  during an unrelated R3/R4 MCS test-table compile failure
  (`test_owned_mcs_connect_initial.cpp`, excess
  `share-finalization-exchange-denials` initializer), so the separately
  registered Python provenance-parser CTest is **NOT RUN** in full CTest at
  this SHA. This does not invalidate the independently green R7 GUI/native
  jobs and is outside R7 ownership.
- Source/CMake/package/authorization review: **PASS by inspection**. Owner
  packaged no-Sharing provenance probe and LLDB backtrace: **NOT RUN**.
  Caller attribution remains **BLOCKED** until the owner's packaged Cocoa
  probe records a matching source/caller; no R4 pixel, monitor profile,
  warning suppression or production color correction changed. R10 still owns
  future accepted-client R2->R3/Share/GraphicsReady composition; R7 adds none.

## R4 admitted-frame delivery / revocation assurance authoring (2026-10-30)

- Authoring parent: `b76f62917479ff3a1e512d7c6c791157d97d2f2c`; current candidate is not manually approved
  for physical testing, so this increment remains offline only.
- Production trace: current R2 authority is checked before graphics write
  authorization/receipt and before/after ACK consumption; R3 maps exact outer
  accepted bytes to frame payload bytes; only the final complete record calls
  R4 delivery completion and creates ACK membership. R3/R2 retirement reaches
  Graphics DVC `close()`, which disconnects R4 and clears its ACK window.
- Coverage gap found: full R3 DATA delivery followed by retirement before ACK
  was not directly composed in one production-lifecycle regression. Existing
  cases covered full delivery -> ACK, pending delivery -> close, and isolated
  R4 generation retirement.
- Added
  `graphics.frame-delivery-session-retirement-before-ack`: exact full frame
  delivery creates one outstanding ACK, DVC retirement clears it, and a late
  ACK is inert/Closed. No production C++ behavior changed.
- Fixed sanitizer census is intentionally unchanged: R3 Graphics DVC 23,
  portable graphics 45, x264/BGRA 29, ClearCodec 4, R5 X11 45. The new
  behavior is ordinary full CTest outside the fixed R3 selector.
- Source/registration review: **PASS by inspection**. Local configure/build,
  focused/full CTest, ASan/UBSan and benchmark: **NOT RUN**. Hosted
  exact-publication-SHA CI: **PENDING**. Physical RDP client/native desktop:
  **NOT RUN / unauthorized**.

## R9 R8-terminalization label failure diagnosis (2026-10-30)

- Exact head `ef807b3f37729523be3514d54ba8122ab47c8090`: independent and primary workflow structure parsing **PASS**, but Ubuntu/Windows protocol, R9 sanitizer, R7 lifecycle/session and bootstrap configure **FAIL** at `tests/CMakeLists.txt:5364`.
- One common cause: `clipboard.file-destination-finalization-generation-replacement` carries forbidden internal label `r8-terminalization`; the repository's durable-label policy intentionally rejects road identifiers.
- R9 correction changes that label only to `protocol;file-destination;terminalization;offline`. It does not add `clipboard`, so the fixed 107-case clipboard sanitizer census is unchanged; exact-name terminalization execution is unchanged.
- Exact correction-SHA hosted matrix **PENDING**. No production code change, manual candidate dispatch, owner-native receipt or physical run.

## R8 terminalization CI-census reconciliation (2026-10-30)

- Current reconciliation parent: c749f938af9217166ae5e20f0dc6f58156cca137. The independent structure failure
  on R8 publication 92f25e6362848c2fb28a397e1f1672a94f2eebdc was real, but
  the subsequent R9 count-only change to 109 followed the initial R8
  registration rather than the owner's explicit requirement to revalidate the
  existing **107-case** clipboard sanitizer selector.
- Corrective test structure: retain both production-backed injected behavior
  modes but expose exactly one ordinary CTest,
  clipboard.file-destination-finalization-generation-replacement, which runs
  macOS then Windows. It is intentionally outside the fixed clipboard label
  census. The sanitizer job first enumerates/runs the unchanged 107-case
  census, then executes this combined terminalization CTest separately under
  the same ASan/UBSan build.
- Workflow validator returns to clipboard_expected_test_count=107 and also
  requires the combined test name. No production R8 code, wire behavior,
  authority, native file access or activation flag changes in this correction.
- Source/registration reconciliation: **PASS by inspection**. Local configure,
  build/full CTest, combined focused CTest and ASan/UBSan: **NOT RUN** in the
  connector environment. Exact-publication-SHA structure/full/sanitizer:
  **PENDING**. Physical clipboard/client/files remain **NOT RUN / unauthorized**.

## R9 current-head structure diagnosis — R8 clipboard inventory 109 (2026-10-30)

- Current audited architectural head: `1042d62715900b585e82da8178715172177728f8`; R10's production commit resets prior candidate qualification.
- Independent structure run `41169537267` fails at the first R9 validator boundary: missing stale required token `clipboard_expected_test_count=107`.
- R8 `92f25e6362848c2fb28a397e1f1672a94f2eebdc` correctly changed primary workflow inventory to **109** and registered two finalization-generation replacement tests. Current workflow contains `clipboard_expected_test_count=109`; both test names are in the registry.
- R9 compared all 376 required workflow tokens against current `ci.yml`; **only** the stale 107 token is absent. Correction changes the validator to 109 only. Exact publication-SHA structure/full hosted CI **PENDING**; owner-local full CTest **NOT RUN** here. Manual candidate and physical testing remain **NOT RUN**.

## R10 macOS accepted-client pre-admission increment (2026-10-30)

**Authoring baseline:** `6a79aa113ae959342013853a9c1e51af80042a8a`
(after reconciling concurrent R2/R8 changes). The existing macOS
`MacRuntimeHostControl::serviceOnce()` now prepares a per-accepted-client
R2 standalone CredSSP acceptor with a private random NTLM challenge, pins
the R10 owner-consent epoch, listener generation and credential generation,
advances the existing R1 X.224/HYBRID Confirm and selected-certificate TLS
owner, and reads/answers one bounded TSRequest step through the existing
R2 framer and writer. It can retain `StandalonePasswordAuthenticatedPrincipalProof`
only after real owned-connection `CredentialsVerified`. It does not call
`completeCredSspAdmission()`, read MCS plaintext or attach
`RuntimePlatformNativeDesktop`; successful authentication remains
pre-admission pending a genuinely protected R2/R3 positive interface.

The new macOS host-control CTest uses a synthetic accepted LAN peer and
partial TPKT to assert zero MCS/Share/native publication and terminal
Stop cleanup. This case is a negative pre-admission regression, **not**
a production-backed successful-credentials/no-native-admission oracle:
that required follow-up remains OPEN. No new 25 ms timer, worker-thread
GUI, second accepted listener, native admission Boolean or desktop route.
Local canonical macOS build/focused/full CTest, sanitizers, exact-SHA hosted
macOS CI and physical Windows App/mstsc: **NOT RUN** at authoring. Next:
hosted same-SHA compile/CTest; R2 publishes a nonforgeable authenticated
macOS admission lease bound to the exact accepted R1 proof and current owner
epoch, R3 publishes protected macOS MCS/GCC/Share consumption, then R10
composes that on the same owner thread and adds a completed-CredSSP
pre-MCS denial and protected positive path. R9 manually qualifies any
future owner candidate; Agent 6/owner separately authorize physical tests.

## R9 same-SHA interop/sanitizer baseline and roadmap guard (2026-10-30)

- Baseline `c88dc60f9e218797ddcd640af6bba1693adca1d7`, [Actions 41167358674](https://github.com/k1moradi/RDP-server/actions/runs/41167358674): Linux **1004/1004** Debug/Release, macOS/OpenSSL4.1 **782/782**, Windows CLANG64 **885/885**; R2/R7/R9/GUI/bootstrap/docs **PASS**. Sanitizer R5 **45/45**, clipboard **107/107**, R3 CAL **9/9**, Graphics DVC **23/23**, R4 x264 **29/29**.
- Downloaded Microsoft interop artifact `13029796352` **COMPLETE_PASS**: production credentials verified, no authInfo empty/failure, bad-binding and required Type-2 AV negatives **PASS**, native admission **NO**. Clean-Windows **QUEUED** and candidate **SKIPPED on push** are distinct.
- R9 adds canonical-roadmap integrity negative CTest and CI guard; local synthetic validator smoke **PASS**; approved owner checkout/full CTest **NOT RUN**; new exact-publication-SHA hosted CI **PENDING**.
- Owner Linux 1060/1060 lacks verified tested SHA/toolchain/configuration/command; M1 owner same-SHA evidence **MISSING**. Manual gate **NOT DISPATCHED**; physical test authorization **NOT GRANTED**.

## R2 macOS nested protected visitor denial — 2026-10-30

- Independent follow-up after R2 published
  `fd0a141b8355cdd7b3f46573fc100ce2d4b7b500`: retain its
  original-grant snapshot and newer-grant preservation semantics.
- Add a scoped owner-thread reentrancy fence over the real
  `MacNativeDesktopAuthorization::visit` native evidence and consumer
  callback. A nested call cannot invoke a second protected consumer;
  current outer grant continues, while revoke/rebind still causes original
  visit denial without erasing an independent replacement.
- Dedicated ordinary
  `security.native-authorization-macos-standalone-nested-visitor-denials`
  CTest reuses the established offline R2 fixture and shared registry.
- Source/registration structure: **PASS by inspection**.
  Local canonical build/full CTest, ASan/UBSan and benchmark: **NOT RUN**
  (approved local checkout unavailable); hosted exact-publication-SHA
  qualification: **PENDING**. Physical client/native admission: **NOT RUN /
  unauthorized**. Agent 3 macOS private R3 positive gate: **NOT PRESENT**
  in inspected `main`; R10 accepted-client/native composition remains
  **BLOCKED**. Next: same-SHA CI and R2/R3 interface coordination.

## R8 terminal FileContents callback reentrancy authoring (2026-10-30)

- Parent SHA: `871c2d34ff5d40344b262483a02c96613cf9c10a`. Audit of current macOS/Windows finishComplete()
  found the unchecked final resize/flush/close callback gap after the
  already-qualified post-write authority check. Source-level counterexample:
  injected callback replaces RemoteTransfer generation and calls
  onRemoteGenerationChanged(); prior outer finishComplete() still assigned
  Complete after callback return, and close could reenter cleanup before
  clearing the owned token. No preexisting regression covered this boundary.
- Minimal production correction: check generation/source epoch before and
  after each terminal callback, mark terminal status before cleanup callbacks,
  and detach owned native token before close. Replacement during resize/flush
  truncates the duplicate; close callback replacement denies completion and
  local path publication without pretending already-closed storage can be
  reopened for truncate.
- Two ordinary production-backed fake-native CTests (macOS/Windows) separately
  cover current-owner success and resize/flush/close replacement with
  reentrant notification. Existing write-time regressions unchanged.
  R9 exact sanitizer inventory 107 -> 109; preserve the original 107.
- Linux direct pwrite/fsync is owner-thread synchronous with no injected
  native reentrant callbacks; unchanged. Single-flight Format Data and
  FileContents requests, monotonic bounded stream IDs, 64 KiB RANGE,
  checked offsets/sizes, bounded PNG/DIBV5 conversion, remote-name/path
  separation and R3-only route/accepted-byte receipt ownership: source audit
  only, no permission changes. R10 activation contract recorded in ROADMAP;
  `kLinuxProductionClipboardActivationApproved` remains false.
- Source/registration review: **PASS by inspection**; local configure,
  compile, focused/full CTest, ASan/UBSan and benchmark: **NOT RUN**.
  Exact-publication SHA hosted CI: **PENDING** until verified artifacts.
  Real clipboard, filesystem copy, native desktop and physical clients:
  **NOT RUN / unauthorized**.

## R5 direct-main owner-private Linux/X11 evidence reconciliation (2026-10-30)

- Compared PR #39 head `e496230a269c87fac5f151ddbed38c44a3472273`
  with subsequent main. The three evidence files and central CTest were missing;
  the R5 native X11 45-case suite, reentrant Damage and synchronous XShm
  callback-retirement coverage, and R2 consent-epoch work had landed independently.
- New offline validation records independently the owner-grant and R2-bound
  consent epochs (including reconnect), rejects mismatches and allows
  admission-before-capture with later Share/frame still **NOT_OBSERVED**.
  The redactor exposes only typed stage outcomes and non-identifying booleans.
- PR historical synthetic 15/15, former hosted 45/45 and R2 evidence are
  **not** new-main receipts. Current publication-SHA full Debug/Release CTest
  and native ASan/UBSan: **NOT RUN** in this environment; GitHub checkout
  DNS resolution unavailable. The owner's 1060/1060 local CTest lacks a
  recorded Git SHA and cannot be qualified against this publication.
- Physical seat0, Sharing, native R2 Admission, first frame/ACK, XTEST,
  RandR, Stop/lock/logout/switch/reconnect **BLOCKED / NOT RUN**; explicit
  separate owner authorization and R9 exact-SHA candidate required.
  Next gate: published-SHA hosted full/focused CTest, 45/45 ASan/UBSan,
  then owner-only physical run following the private procedure.

## R1 Type-2/FIN source audit and post-Type-2 TCP reset test (2026-10-30)

- Baseline: c88dc60f9e218797ddcd640af6bba1693adca1d7. Read all
  required project policies, the single R1 socket/BIO/SSL owner,
  the R10 pre-admission scheduler, bounded CredSSP reader/writer and
  relevant real-socket Direct-NTLM CTest registration and assertions.
- Owner-provided 9.5-ms local Type-2-commit to TCP FIN: zero
  subsequently observed encrypted/plaintext TLS bytes, no Type 3,
  close_notify or alert. The server's local R1 SSL_write_ex completion
  and generation-pinned releaseReply() do not prove peer receipt.
  This observation does not establish credential failure or a
  timeout/performance target.
- Existing negative cases already cover silence, orderly FIN,
  TLS partial record, queued one-byte DER plaintext then FIN,
  complete non-Type-3 TSRequest, close_notify, fragmentation and
  same-listener retry. Review found no production R1 change justified.
  A real post-Type-2 RST was only asserted absent in those FIN tests.
  New runtime.linux-direct-ntlm-post-type2-abortive-reset-classification
  adds a zero-linger RST, explicit PeerReset classification, zero new
  application authority and FIN-only timestamp non-availability;
  existing CTest executable and registry are reused. No production
  source, wire format, policy, timeout or new build root.
- Timing/counter review: monotonic steady_clock observations,
  availability flags separate from zero durations, bounded/saturated
  cumulative counts, first encrypted-byte latency latched only on
  actual receive delta, FIN-only Type-2-to-peer-EOF timestamp, and
  wall Read/Write dwell distinguished from non-additive poll and
  ready-to-service subsets. The Type-2 local write is not a TCP ACK.
- Exact baseline Actions 41167358674: protocol macOS job
  124437727562 PASS on OpenSSL 4.1.0, Ubuntu protocol
  124437727625 PASS, Windows protocol 124437727522 PASS, and
  R9 sanitizers 124437727576 PASS. Overall workflow still queued
  for clean-Windows self-hosted job at inspection. New-regression
  local focused/full Debug/Release CTest, ASan/UBSan: NOT RUN
  (no approved ~/rdp-server/build checkout in connector environment).
  Exact-publication-SHA CI PENDING; physical client NOT RUN and
  unauthorized. Next gate: same-SHA hosted test evidence, R9 manual
  owner candidate and separately authorized paired R6 client trace.
  The unresolved external boundary is client receipt/processing of
  Type 2 and the true initiating cause of its FIN.

## R2 macOS grant reentry hardening, R3 private-gate audit — 2026-10-30

- Audited main base `c88dc60f9e218797ddcd640af6bba1693adca1d7` and existing R2 native authorization,
  standalone credential proof, Linux R2 broker and R3 private-friend boundary.
- R2 visitor now pins its original generation and callback-local evidence
  across synchronous revocation/rebinding; consent epoch is checked after
  the native evidence callback. A later independent grant is not retired by
  the stale visitor.
- Dedicated ordinary CTest:
  `security.native-authorization-macos-standalone-reentrant-generation-denials`.
  Production-backed R2 with synthetic fixtures; no native OS lease or R3
  authority is manufactured.
- Local canonical Debug/Release build, CTest and sanitizer: **NOT RUN** (no
  approved checkout/build root in connector runtime). Exact publication-SHA
  hosted qualification **PENDING**; no CI PASS is claimed.
- Private R3 first-MCS friend is Linux-only at this base; macOS protected
  transitions remain **BLOCKED**, and physical native admission **NOT RUN /
  unauthorized**. Next: Agent 3 interface agreement, R10 accepted-client
  composition, same-SHA CI/R9 and separate owner authorization.

## R1 OpenSSL 4.1 typed-stack macro compile follow-up — 2026-10-30

- Previous R1 publication `e43414099f5451d59538668445fdcf3764e153b3`:
  Ubuntu, Windows, CLANG64, R9 sanitizers and macOS protocol jobs **PASS**.
  macOS job `124406000069` resolved OpenSSL **4.0.3**, and the dedicated
  `runtime.tls-endpoint-san-only-openssl-compatibility` passed in Debug and
  Release; this does **not** prove 4.1 source compatibility.
- Current failing descendant `a267f37c4df9e8ac69c67e6ef165fa3db7dbae0f`,
  macOS protocol job `124407094700`: **FAIL at compile**, OpenSSL **4.1.0**,
  AppleClang 21, first boundary `runtime_tls_context.cpp:317` where
  `::sk_GENERAL_NAME_value` expands as an OpenSSL typed-stack macro and is
  invalid after the C++ scope operator. R7's current dependency audit confirms
  the same R1-owned boundary; R3/R6/R7 production work is not the cause.
- Correction removes only the `::` prefix from generated
  `sk_GENERAL_NAME_num/value/push` macro uses in production and the matching
  test helper. No SAN policy, wildcard/CN behavior, trust-chain verification,
  TLS version, Type-2 bytes, polling, timeouts, socket/SSL ownership or native
  admission changes.
- Local canonical build/focused/full Debug/Release and sanitizers: **NOT RUN**
  (approved checkout unavailable). Corrective exact-publication-SHA macOS
  OpenSSL 4.1, Linux, Windows and R9 sanitizer qualification: **PENDING**.
  Benchmark **NOT RUN / not applicable**. Physical RDP testing remains
  **NOT RUN / unauthorized**.

## R7 callback-retirement hosted qualification and dependency recheck — 2026-10-30

- Qualified implementation SHA:
  `34e508105d7f7f9f503d3d29475949269dd370cf`.
- Primary workflow `41157153368`: macOS native lifecycle
  `124407093817` **PASS**, including
  `macos.native-desktop-owner-borrow-callback-retirement` in Debug and
  Release focused selections (22/22 each); macOS protocol
  `124407093927` **PASS** with the new regression in ordinary full CTest;
  macOS portable GUI `124407094074` **PASS**; macOS session sanitizers
  `124407093868` **PASS**; R9 security/protocol sanitizer
  `124407093911` **PASS**; macOS/Ubuntu owner GUI parity
  `124407093974` / `124407093879` **PASS**.
- R9 GUI Round 2 job `124410451261` **PASS** and emits
  `GUI ROUND 2 PASS: 34e508105d7f7f9f503d3d29475949269dd370cf`.
  The self-hosted clean-Windows job is a distinct release-evidence track and
  remained queued; it is not a prerequisite for this R7 native/macOS fix.
- Descendant audit head `a267f37c4df9e8ac69c67e6ef165fa3db7dbae0f`: R7 macOS native lifecycle, portable GUI,
  session sanitizers, owner GUI parity and Round 2 remain **PASS**. The
  descendant macOS protocol job `124407094700` fails at compile time in
  R1-owned `runtime_tls_context.cpp` with OpenSSL 4.1 expansion of
  `::sk_GENERAL_NAME_value`; no R7 source participates.
- **New local observation, 2026-10-30:** owner-reproduced diagnostic
  `QColorSpace attempted constructed from invalid primaries` followed by four
  `QPointF` coordinates. Qt6's `qcolorspace.cpp` contains the emitting
  failed-`PrimaryPoints::isValid()` branch. The emitter is confirmed in
  upstream Qt source; the caller, specific Qt build, Cocoa plugin and monitor
  ICC/EDID provenance are **NOT VERIFIED**, so Qt/driver/project blame is
  unproved. No raw host trace or profile was supplied to this review.
- First-party route audit **PASS by inspection** on parent `eade2780c171fc2f9d0292f19bbbf1cba8f6422b`:
  `QApplication`/widget-style startup can invoke Qt platform internals;
  the existing `gui.round2-qcolor-warning-classification` guard checks all
  `src/*.{cpp,h,mm}` for application `QColorSpace` and message-handler
  construction. The ScreenCaptureKit stream fixes output to BGRA and passes
  checked pixel buffers, dimensions and geometry, without passing ICC/EDID
  data to Qt. The extracted package contains the QtGui framework and Cocoa
  platform plugin; monitor-profile use inside Qt remains an unverified route.
- Opt-in no-Sharing attribution instructions are recorded in the existing
  R7/R9 testing-standard section: exact package/SHA and version inventory,
  offline `QT_QPA_PLATFORM=offscreen` comparison, no-argument Cocoa
  `QT_DEBUG_PLUGINS`/message-pattern repro, and only if needed LLDB
  QColorSpace constructor-call stack. Keep raw paths and logs private;
  record only redacted module names, Qt version and result.
- Actual owner macOS trace, package/no-listener re-execution, local canonical
  compile/full CTest, offscreen GUI CTest and LLDB: **NOT RUN** here (no
  approved macOS checkout/app/runtime). Existing R7 callback-retirement
  Debug/Release 22/22 qualification remains unchanged. Main's pre-Type-3
  incomplete-authentication wording and password redaction, and the
  no-argument/Sharing OFF package smoke tests, were audited by source/test
  inspection only; no new PASS is claimed. No code, profile, OS state,
  server, TCC or capture changes were made. Next: private owner trace +
  same-SHA CI/R9 review before any code-level color intervention.
- Current macOS HostControl still does not positively call
  `RuntimePlatformNativeDesktop::attachAuthenticatedSession()`. Native
  readiness therefore remains impossible from TCP/TLS/Username/
  CredentialsVerified/GUI Sharing alone. R10/R2 must supply the future genuine
  accepted-client authenticated/admitted authority; R7 does not duplicate it.
- Local canonical build, local offscreen/package warning reproduction and
  physical native desktop: **NOT RUN**. Hosted R7 implementation evidence is
  complete; live native attachment remains **BLOCKED** on R10/R2 composition,
  manual R9 exact-SHA candidate qualification and separate owner permission.

## R6 private two-client A/B validation authoring — 2026-10-30

- Reviewed current main and existing R5 macOS evidence path, MSVC/CLANG64
  SSPI oracle, and WTS/DXGI/SendInput offline negative suites. Existing
  recorded Windows receipts: delegated positive reaches production
  CredentialsVerified=yes, authInfo failure=none, empty fields=none,
  native admission=no, bad binding denied before authInfo and malformed
  required-AV controls negative. New-head Windows exact-SHA qualification
  remains PENDING/NOT RUN; prior receipts are not new-sha proof.
- Added closed-schema read-only scripts/windows_client_ab_evidence.py,
  12 paired evidence cases on the existing R5 synthetic fixture and the
  dedicated offline CTest
  interop.windows-client-ab-evidence-contradiction-denials.
- New-script Python py_compile PASS; seven local synthetic logic checks
  using a stub R5 provider PASS (not full integrated tests). Full CTest,
  Linux/macOS/Windows exact-head jobs and live A/B NOT RUN in this
  connector-only environment.
- No protocol Type-2/TLS, Windows WTS/DXGI/SendInput production code,
  OS credential stores, desktop capture or injection changed.
  Next: run full CTest and Windows exact-head oracles, reconcile R9
  candidate and obtain separately authorized private A/B physical proof.

## R7 macOS frame borrow reentrant owner retirement (2026-10-30)

- Authoring parent: `033061f53cc715368d92eb27ee9cb4d14742caf9`.
- Source defect: the R4 borrowed-frame callback ran under
  `FrameMailbox::mutex_`; synchronous owner revoke attempts the same mutex
  during native retirement. The mailbox now releases the mutex across consumer
  invocation, holds its arena until any in-flight borrow completes, discards
  concurrent capture writes and fences a retired generation to denial.
  `borrowAuthorized()` locally pins the shared mailbox across revocation.
- New Apple-only offline CTest:
  `macos.native-desktop-owner-borrow-callback-retirement`, registered in
  ordinary CTest and both Debug/Release focused macOS lifecycle CI selects;
  checks original frame bytes remain accessible after callback-time revoke,
  denied publication, one-time capture/watch retirement and no input post.
- QColorSpace remains unattributed: no project `QColorSpace`, Qt custom
  primaries/ICC conversions or warning suppression in inspected GUI/macOS
  sources/assets; existing CMake policy checks all first-party source.
  No offscreen/package reproduction here (Qt6/macOS checkout unavailable).
- Source/CTest/CI review: **PASS by inspection**. Local canonical
  Debug/Release, offscreen/package, ASan/UBSan, and native execution:
  **NOT RUN**. Exact-publication-SHA hosted macOS and owner GUI evidence:
  **PENDING**. Physical desktop/TCC/client: **BLOCKED / NOT RUN**.
- R10 alone composes accepted-client R2 authenticated/admitted proof into
  `RuntimePlatformNativeDesktop::attachAuthenticatedSession()` and retires
  the native generation on authority loss; no R7 direct attachment or R10
  authentication state machine was added.

## R3 pure protocol post-Connect-Response domain ordering — 2026-10-30

Source baseline: `e43414099f5451d59538668445fdcf3764e153b3`. Added
`transport.mcs-session-post-response-domain-ordering-denials` through
the existing production R3 state machine and private test-only friend.
Verified MS-RDPBCGR basic-settings/channel ordering and MS-RDPELE personal
terminal-server CAL decision by normative review. Source and CTest
registration inspection: **PASS**; compile, focused/full CTest, R9
sanitizers and macOS/OpenSSL 4.1 CAL suite: **NOT RUN** (no approved
`~/rdp-server/build` checkout). Exact-publication-SHA hosted CI:
**PENDING**. Native R2 admission / Microsoft client / graphics:
**NOT RUN / unauthorized**. No benchmark. Next live proof is one
genuine native R2 lease revalidated at first MCS read, semantic
dispatch, protected writes and accepted-byte receipts.

## R1 OpenSSL 4.1 SAN-only endpoint matching compatibility — 2026-10-30

- Authoring source SHA: `7a065715165b342786f7e8f53c7154572f542e85`; publication SHA must be taken from the atomic main commit. No separate branch, TLS/security policy modification, or physical test.
- **PASS by inspection only:** version-gated selected-leaf SAN matching replaces deprecated X509_check_ip_asc/X509_check_host only under OpenSSL 4.1+. It never invokes X509_verify_cert, trusts a chain, grants native Admission or opens a listener. Older OpenSSL/LibreSSL retain current X509_check semantics. Test-side deprecated ASN1_STRING_length calls are version-gated.
- **Dedicated registered CTest:** `runtime.tls-endpoint-san-only-openssl-compatibility` (production runtime TLS executable, offline secure certificate-file fixtures): IPv4/IPv6, exact DNS, wildcard/partial-wildcard, CN-only, malformed/NUL/overlong, missing SAN/certificate status.
- **Owner-local build/focused/full Debug/Release/ASan/UBSan: NOT RUN** — approved `~/rdp-server/` checkout absent, GitHub DNS unavailable. **Exact publication-SHA hosted macOS/OpenSSL 4.1, Linux/older OpenSSL, Windows, sanitizer: PENDING**, with no receipt asserted. Requested commands: canonical CMake Debug build/full CTest, `ctest --test-dir build -R '^runtime.tls-endpoint-san-only-openssl-compatibility$' --output-on-failure`, applicable Release CTest and CI. Benchmark **NOT RUN / not applicable** (no I/O or hot-path behavior changed).
- **Physical client evidence: NOT RUN / unauthorized.** TLS Type-2 write remains local transport evidence only, never peer receipt. Next owner R9: record first failing hosted boundary and exact SHA before candidate promotion.

## R8 FileContents native-write generation replacement authoring evidence — 2026-10-30

- Authoring parent: `dd85139f59b4ef155a8bb544d29e4c2f90c28feb`.
- Selected uncovered path: a correlated FileContents RANGE result reaches the
  native destination, whose synchronous write callback replaces the remote
  clipboard generation before returning. Existing tests covered replacement
  before destination consumption, stale stream responses, partial R3 writes,
  destructor cancellation and completed-source-epoch revocation, but not this
  callback-time transition.
- Correction: macOS and Windows callback-driven file destinations revalidate
  the exact generation/source epoch after successful native write and before
  advancing `bytesWritten_` or completion. Stale bytes are truncated and the
  owned duplicate is closed; remote file names remain metadata only.
- New offline CTests:
  `clipboard.macos-file-destination-write-generation-replacement` and
  `clipboard.windows-file-destination-write-generation-replacement`. Shared
  clipboard sanitizer inventory: 105 -> 107 with exact-name sentinels.
- Source audit: FileContents SIZE/RANGE retains a single outstanding owner,
  monotonic stream identity, bounded 64 KiB RANGE requests, checked
  offset/length/file-size arithmetic and generation-scoped draining. PNG/DIBV5
  stored/decode bounds and UTF-16 name validation are unchanged.
- Exact publication-SHA focused/full/ASan/UBSan qualification: PENDING.
  Local canonical build root: NOT RUN in this GitHub-connector environment.
  Live clipboard, real file-copy and physical-client acceptance: NOT RUN.
  Linux production clipboard activation remains false.

## R6 OpenSSL 4.1 CredSSP selected-certificate length compatibility — 2026-10-30

- Failure baseline: `8249dd3d948b6d598deb4564f4820f8863292c7d`;
  reconciled publication parent: `d4821dacb33f03bbf34d177f2e704aeeac2fe6e3`.
- Current macOS producer failure: AppleClang/OpenSSL 4.1 treats
  `ASN1_STRING_length` in `credssp_tls_certificate.cpp` as a deprecated
  warning and the project correctly promotes it to an error.
- Narrow correction: OpenSSL 4.1+ uses `ASN1_STRING_get_length`; older
  OpenSSL/LibreSSL keep the previous accessor and all existing selected-key
  bounds/borrowing semantics.
- Added ordinary offline
  `security.credssp-active-tls-public-key-length-portability`, using the
  existing real TLS fixture and independent binding-hash equality check.
  Existing SSPI oracle and negative controls are unchanged.
- Source/CTest registration inspection **PASS**. Local canonical build/full
  CTest and benchmark **NOT RUN** in connector-only authoring. Exact-SHA hosted
  macOS/Linux/Windows and R9 qualification **PENDING**. Physical client/native
  desktop remains **NOT RUN / unauthorized**.

## R10 dependency-graph recovery after concurrent ROADMAP truncation — 2026-10-30

- Current-head audit found `docs/ROADMAP.md` at `8249dd3d948b6d598deb4564f4820f8863292c7d` was a zero-byte blob, dropping the living TODO and all R10 dependency sections despite Agent 3's intended CAL-cardinality entry.
- Restored the exact parent roadmap from `4a79a54ff397a6aaff61ee048d2850fda8483159` and prepended Agent 3's intended `R3 P0 follow-up — CAL test registry compile blocker found and corrected` entry from the published commit diff. No milestone content was intentionally removed.
- R2's prepared owner-consent epoch source gap is resolved by `e469ce9707965c888988fc27c4134acccfd31b1a`; R10 consumes that through the existing broker/lease only.
- Current exact-head structure guard `41115191080` **PASS**; primary workflow `41115190802` was **IN PROGRESS** when inspected. No manual `r9_credssp_owner_candidate=true` workflow dispatch was present. Therefore physical native admission remains **BLOCKED / NOT RUN / unauthorized**.
- Production code, CTest inventory and runtime behavior: **UNCHANGED**. This commit repairs canonical documentation state only.

## R3 CAL dispatch-table compile blocker follow-up — 2026-10-30

- Exact implementation SHA `e6293ca6fc860ccec651793952c23e2b460576ff`
  reached the shared MCS/CAL test translation unit on all protocol platforms.
- Failure was test-registry cardinality, not the production licensing helper:
  170 behavior entries were initialized into
  `std::array<McsTestCase, 169>`.
- macOS job `124254320590`: **FAIL**, excess elements in array initializer
  after `rdp-server-protocol` (including `rdp_licensing.cpp`) built.
  CMake selected OpenSSL 4.0.3, so this does not prove the 4.1+ branch.
- Ubuntu `124254320684`: **FAIL**, too many initializers.
- Windows `124254320603`: **FAIL**, C2078/C2131 at the same table.
- R9 ASan/UBSan `124254320460`: **FAIL**, excess elements in array initializer.
- Correction: fixed bound 169 -> 170 only; production source, CTest names,
  CAL 9-case selector and sanitizer sentinels unchanged.
- Current dependency chain:
  `test_owned_mcs_connect_initial -> rdp-server-protocol +
  rdp-server-runtime-licensing -> OpenSSL`.
- R2 consent-epoch fence is present on current main via
  `e469ce9707965c888988fc27c4134acccfd31b1a`; no R3 bypass or synthetic
  native admission was added.
- Local canonical build/full CTest/sanitizers: **NOT RUN**; approved local build
  root unavailable in this connector environment.
- New exact-SHA hosted matrix/sanitizer: **PENDING** until this correction is
  published and Actions completes. Physical client/native admission:
  **NOT RUN / unauthorized**.

## R5 in-flight XShm borrow terminal retirement — 2026-10-30

- Authoring parent `dc9f142593f87bc249b512bca61a56ab1aade5d6`. New `x11.desktop-resource-inflight-frame-borrow-authority-retirement` in production-linked existing Xvfb target; callback reads synthetic pixels and then retires current aggregate before returning `true`. `consumeR4Frame` must return `false` and a fresh owner must reject old generation, old Damage and stale frame access.
- Existing authority audit: R10 `GraphicsReady` and accepted-client R2 `visitNativeDesktopSelection` create resources; R2 revalidates concrete live lease, consent, owned R1/TLS/principal and logind before/after visitation. Terminal XTEST cleanup remains no-post; graceful disconnect can release held keys/buttons while authorized. No production code, real desktop, clipboard, input or capture changed.
- CTest/source/CI selector inspection **PASS** at authoring; R5 explicit native ASan/UBSan selector is now 45 names, with fail-closed name and count sentinels in workflow and validator. Local compile/CTest/Xvfb/ASan/UBSan **NOT RUN** (no approved checkout and no GitHub DNS); exact-publication hosted tests **PENDING**. Previous 44/44 hosted qualification remains PASS on `434ac8fe600e9aa6fdf7ede842d67d6f662457f3`, not yet on this increment.
- Private macOS Windows App owner manifest v2/redacted summary v1 reviewed: SHA, client, credentials-matched boolean, correlation and stage/timing outcomes preserved; sensitive exact fields redacted. It cannot authorize an R2 lease or represent Linux seat0/UID/lock/consent generation by itself. The future owner-private Linux acceptance ledger and redaction contract are in `docs/ROADMAP.md`.
- Physical Linux native admission, real capture/frame ACK, input, resize, lock/logout/switch/Stop and reconnect **BLOCKED / NOT RUN / not authorized** pending R9 exact-SHA/manual dispatch and real R2 lease. Current global macOS R3/OpenSSL 4.1 CI repair remains separately owned; do not attribute it to R5. Benchmark **NOT RUN**.

## R1 queued plaintext before FIN exact-SHA qualification — 2026-10-30

- Implementation: `452ce336efcb779adb21979f7c22a63bf23535c9`.
- Structure workflow `41111017232`: **PASS**.
- Primary workflow `41111017558`, Ubuntu `124253216902`: Debug full CTest
  **994/994 PASS**, Release full CTest **994/994 PASS**.
- Dedicated
  `runtime.linux-direct-ntlm-post-type2-partial-tsrequest-fin-drain`:
  **PASS**, 0.17 s Debug / 0.22 s Release.
- R9 ASan/UBSan job `124253217087`: **PASS** and modified lifecycle target
  compiled; the explicit direct-run inventory does not select the new mode, so
  that mode's sanitizer execution is **NOT RUN**.
- macOS protocol `124253216884`: Debug/Release **773/773 PASS** using
  OpenSSL 4.0.3. The former hosted OpenSSL-4.1 compile failure is absent from
  this exact run; no 4.1 source-compatibility claim is made.
- Production source changes: **NONE**. Local canonical build/CTest:
  **NOT RUN**. Physical client/server and OS/network changes:
  **NOT RUN / unauthorized**. Benchmark: **NOT RUN / not applicable**.
- R1 remains evidence-bound: local Type-2 TLS commit is not peer receipt. Only a
  same-attempt Agent-6 client observation correlated to R1's exact
  listener/accepted-client generation and post-Type-2 byte/alert/FIN fields may
  legitimately reopen transport.

## R2 native Admission consent-epoch continuity — 2026-10-30

- Authoring baseline: `c82988ee8178294d986e86a3c0cb09801f9bee5b`; current security decision: **missing admission-time consent fence, corrected in production source and offline regression**.
- Inspected `CurrentOwnerSharingAuthority` atomic revoke/generation, `LinuxConsoleAdmissionBroker::prepareAdmission()` and `issueWithSources()`, `LinuxConsoleAdmissionLease`, the exact R1 `completeCredSspAdmission()` call, and protected broker/R3 revalidation. Owner commands are serialized; atomic revocation and evidence-call reentrancy require comparing the exact prepared grant epoch before lease publication. Original code did not.
- R2 correction captures owner epoch once, checks after evidence and after proof/R1 completion, stores it in private lease control and denies old-epoch use on each protected broker revalidation. Failure taxonomy `OwnerConsentMissing` retained. No standalone CredSSP, NTLM/pubKeyAuth/authInfo/password, R1, or R10 controller change.
- Dedicated ordinary Linux behavior CTest `security.linux-native-admission-prepared-consent-epoch-denials` covers no grant, revoke, replacement, permission scope, session generation and callback revocation without issuing a synthetic lease; sanitizer CI pins the exact one-case selection. Prior policy/credential/proof and MCS negative tests remain.
- Original production epoch implementation source/CTest/CI review: **PASS**; later Ubuntu full, portable-bootstrap and R9 sanitizer compilations exposed a separate stale GSSAPI test friend seam that did not supply the two new preparation outputs.
- P0 fixture repair: `tests/test_linux_gssapi_spnego.cpp` now retains one test-only `PreparedAdmissionState` holding the exact policy generation and owner-consent epoch, passing both unchanged through split `prepare`/`complete` and the combined helper. Existing policy-generation mutation remains; a same-permission consent replacement between phases must fail with `OwnerConsentMissing`. The independent `security.linux-native-admission-prepared-consent-epoch-denials` test and the R9 selections remain unchanged. No production implementation or verifier change.
- Repair source/caller/registration review: **PASS**. Local canonical compile, Debug/Release full/focused CTest, sanitizers and benchmark: **NOT RUN** (no approved checkout in this connector). Corrected exact-publication-SHA hosted Linux, R9 ASan/UBSan, and both runtime-security dependency modes: **PENDING** until their actual receipts are inspected. Physical native OS admission, capture/input/clipboard: **NOT RUN / unauthorized**.
- Next gate: exact-publication-SHA full hosted tests and sanitizer evidence; only afterward, separate authorization for genuine owner-session/mstsc/native admission and first MCS.

## R8 partial-receipt fixture borrowed-view correction — 2026-10-30

- Parent `c75cf533e2d1fab238ad9781ed6da50db2770cc3` has the source-loss bridge/CTest/CI increment.
- The dedicated test now uses `recordAcceptedWriteReceipt` with stable
  route/reply/slice/offered-byte scalars copied before R3's positive partial
  accepted-byte mutation, as mandated by the sole-writer ownership contract.
- Production bridge, all other tests, 105 clipboard sanitizer inventory,
  `kLinuxProductionClipboardActivationApproved = false`: **UNCHANGED**.
- Local canonical full/focused CTest and ASan/UBSan **NOT RUN**;
  exact publication-SHA hosted qualification **PENDING**.
- Physical clipboard, user files, client: **NOT RUN**.

## R8 native source-loss Format List response fence — 2026-10-30

- Authoring parent: `3ebbccef29c2a011ab7a33f5e140c55bb3107e57`, atomic direct-main source/CTest/docs.
- Previously uncovered: native source destroyed with no replacement after
  Delivered server Format List, then late CB_FORMAT_LIST_RESPONSE OK.
- Production: exact-generation local revocation invalidates old receipts,
  keeps old response for Superseded drain, cancels unqueued staged bytes
  and retires R8 on R3-bound ambiguous writes. New native generations
  require fresh R2/R3 route authorization.
- New offline test:
  `clipboard.route-bridge-server-local-source-revocation-response-drain`.
  R9 sanitizer count 104 -> 105, CI/validator exact-name guards.
- Canonical local focused/full/ASan/UBSan: **NOT RUN**; no approved
  checkout/network access. Exact publication-SHA hosted: **PENDING**.
- `kLinuxProductionClipboardActivationApproved = false` unchanged;
  physical clipboard, user files, client acceptance **NOT RUN / unauthorized**.
  Benchmark **NOT RUN / not applicable**.

## R10 first-positive admission integration audit and one-attempt physical receipt — 2026-10-30

- Source audit parent: `452ce336efcb779adb21979f7c22a63bf23535c9`. Read AGENTS/vision/roadmap, coding/testing/compile/benchmark standards and validation; traced R1 `OwnedPreauthTcpConnection`, R2 proof/broker, R10 `advanceAcceptedClientOnce()`, R3 MCS/Share, R4 frame ACK, R5 X11, R7 HostControl and R8 dormant clipboard.
- **PASS by inspection**: the same R10 serialized service step calls `issueAdmission()` after `CredentialsVerified`; successful broker issuance is the sole path to first bounded R1 MCS intake; R2 revalidates before TLS read and at complete R3 Connect-Initial. Buffered trailing TLS plaintext is not consumed by the CredSSP reader. Existing valid-authInfo + 416-byte Microsoft MCS CTest is **negative/denial only**.
- **R2 consent-epoch contract resolved:** production R2 now captures the prepared `OwnerSharingAuthorizationEpoch`, rechecks the same epoch after native evidence and after proof/R1 completion, retains it in the private lease control and requires it during every protected broker revalidation. R10 continues to consume only `issueAdmission()` / the authoritative R2 lease and `visitNativeDesktopSelection()`; no R10 Boolean, cached epoch or second authority controller was added.
- **Teardown audit:** current Stop order is owner consent revoke -> prepared clipboard/X11 native retirement -> accepted R3/R2/graphics/receipt retirement -> R1 TLS/socket -> listener. This is native-first relative to R3, not the proposed R3-first destructor order. No reentrant defect reproduced; retain no-XTEST, single owner and R1-last until a concrete failing regression justifies a coordinated change.
- **First positive evidence gap:** no genuinely admitted production client MCS/Share receipt. `SSL_pending()`-only readiness for a separate already-buffered but undecoded TLS record is a future R1-specific diagnosis **only if** a real admitted client first stalls at MCS; no reproduction or TLS change claimed. Physical Windows App's first reported boundary remains no observed Type3 following locally committed Type2.
- R7 typed authInfo, R5 native lifecycle, R4 ACK and R8 dormant bridge retain their qualified offline receipts. `kLinuxProductionClipboardActivationApproved = false` unchanged. R6's `docs/MACOS_WINDOWS_APP_OWNER_EVIDENCE.md` owns the client A/B credential procedure; the first native-server receipt checklist and exact cross-agent critical path are in the new top-level `docs/ROADMAP.md` entry.
- Current HEAD `452ce336efcb779adb21979f7c22a63bf23535c9`: workflow structure `41111017232` **PASS**, main protocol workflow `41111017558` **IN PROGRESS** when inspected. R3 committed the OpenSSL 4.1 CAL accessor fix and focused signed-content CTest at `e6293ca6fc860ccec651793952c23e2b460576ff`; its same-SHA macOS/Windows/Linux and R9 sanitizer qualification is still pending, so the old matrix blocker is not yet closed.
- Local canonical configure/build/full CTest, sanitizer and benchmark: **NOT RUN**, approved checkout/build root unavailable. Physical admission/client/desktop/clipboard: **BLOCKED / NOT RUN / unauthorized**. R2's source-level consent-epoch blocker is resolved; Agent 3's CAL dispatch-cardinality correction is now on current main. The remaining gate is exact-head Linux/Windows/macOS + sanitizer qualification, followed by a manually dispatched R9 owner-candidate PASS and separate explicit owner permission before one first-failure physical attempt.

## R3 P0 macOS OpenSSL 4.1 CAL empty-content compatibility — 2026-10-30

- Reconciled base `dc9f142593f87bc249b512bca61a56ab1aade5d6`; concurrent R1 and R6
  changes are retained.
- Conditional `ASN1_STRING_get_length` (OpenSSL 4.1+) versus
  `ASN1_STRING_length` (pre-4.1 OpenSSL/LibreSSL) replaces the one
  zero/nonzero length predicate without casts, altered policy or
  warning suppression.
- CTest `transport.licensing-client-cal-signed-content-empty-only`
  covers absent/present-empty PKCS#7 SignedData accepted and nonempty
  `UnsupportedContainer`; existing issuer/chain/malformed cases kept.
- R9 CAL sanitizer count 8 -> 9, exact-name sentinel and validator
  synchronized. Separate 94-case licensing selector unchanged.
- Source/registry inspection **PASS**. Local CMake build, focused/full
  CTest, ASan/UBSan **NOT RUN** (no `~/rdp-server/build`; GitHub DNS
  inaccessible). New-SHA hosted macOS compile, Linux/Windows and
  sanitizer evidence **PENDING**, not yet a verified macOS fix.
- R9 handoff: validate exact published SHA in platform matrix before
  owner-candidate approval. Native admission/physical client
  **BLOCKED / NOT RUN** without explicit R9 authorization.

## R6 client-path and Windows-native round-one audit — 2026-10-30

- Audited `main` baseline `c82988ee8178294d986e86a3c0cb09801f9bee5b`,
  existing Microsoft CredSSP fixture, production
  `StandaloneCredSspNtlmAcceptor`, private schema-v2 macOS evidence and
  WTS/DXGI/SendInput adapters with their existing offline cases.
- Existing exact-SHA Microsoft MSVC/CLANG64 `COMPLETE_PASS` receipts:
  `ISC_REQ_DELEGATE` positive, terminal returned flag observed as
  `delegation-returned=no`, nonempty authenticated final credentials,
  `native-admission=no`; mismatched binding rejected before authInfo.
  This is **PASS** as an offline oracle only.
- Private physical traces show Type 2 committed, no later server-observed TLS
  bytes, Type 3 not received and FIN. They establish no client-selected
  credential, client Type-2 consumption, specific trust error or policy cause.
- Windows native read-only code audit **PASS by inspection**; existing tests
  already cover WTS SID/LUID/session mismatches, DXGI access-loss and
  callback-time retirement, generation-invalid input and SendInput revocation.
  No demonstrated missing negative boundary; no C++ code or CTest modification.
- The precise macOS Windows App versus Windows 11 mstsc owner-run worksheet,
  privacy rules, stop/invalid-pair rules and hypothesis discriminators are
  maintained in `docs/MACOS_WINDOWS_APP_OWNER_EVIDENCE.md`.
- Source/procedure review **PASS**; local canonical build, ordinary full CTest,
  live physical A/B, real desktop capture/input and benchmarking **NOT RUN**.
  Next: common-descendant whole-project R9 producer qualification, manual
  owner-candidate PASS and separate owner authorization, then private A/B.

## R1 receipt audit + queued plaintext before FIN regression — 2026-10-30

- Authoring parent: `c82988ee8178294d986e86a3c0cb09801f9bee5b`.
- Production receipt audit: **PASS by source inspection**. Type-2 queueing is
  neither TLS completion nor peer receipt. Type-2 "delivered" is set only after
  the exact R1 TLS writer accepts all plaintext and `releaseReply()` revalidates
  transport generation, SSL identity and certificate; source comments and the
  GUI describe this as a local TLS commit, not remote consumption.
- Cumulative post-Type-2 encrypted bytes come from the sole connection-local
  native receive counter; EOF contributes zero bytes. TLS alert/close_notify and
  TCP EOF/reset are terminal classifications from the same SSL/socket owner.
  HostControl snapshots terminal diagnostics before owner cancellation and a
  replacement accepted client receives fresh connection-local counters/timing.
- New production-backed negative:
  `runtime.linux-direct-ntlm-post-type2-partial-tsrequest-fin-drain`. The peer
  queues one TLS application record containing one partial DER byte and then a
  TCP FIN before server servicing. Expected: encrypted bytes observed, exactly
  one plaintext/partial TSRequest byte, no complete TSRequest or TLS alert,
  terminal peer EOF, and no MCS/Share/native authority.
- Existing immediate-retry coverage remains the fresh same-listener TLS/NTLM
  generation gate after terminal pre-Type-3 FIN; large final-authInfo and
  interleaved-WANT cases are unchanged.
- Local canonical build/focused/full CTest/sanitizers: **NOT RUN** (no approved
  `~/rdp-server/` checkout/build root). Exact publication-SHA hosted CI:
  **PENDING**. Physical client/server, service restart and OS/network mutation:
  **NOT RUN / unauthorized**. No benchmark.

## R3 CredentialsVerified -> native Admission -> MCS authority boundary — 2026-10-30

- Authoring parent: `d31b0fa6c20a63eb7c17c388866a5ffb9453acce`.
- MS-RDPBCGR/MS-RDPELE sequence and PersonalDesktop licensing semantics:
  **rechecked**; no wire behavior changed.
- Production R2/R3 audit: **PASS by inspection**. A current independent native
  lease is required before first-MCS TLS intake and again at complete
  Connect-Initial semantic dispatch; later MCS/ClientInfo/licensing/Share/VC
  plans and accepted-byte receipts reauthorize current authority.
- Strengthened existing production-backed lifecycle CTest:
  `runtime.linux-direct-ntlm-final-authinfo-large-fragments-coalesced-tail-reconnect`.
  Its final valid authInfo TLS write now appends the exact checked-in 416-byte
  Microsoft Connect-Initial. The expected boundary is
  `CredentialsVerified=yes`, native Admission denied, all 416 MCS bytes
  outside CredSSP accounting, MCS/Share false and native/clipboard/graphics
  dormant. No synthetic lease is used.
- R9 Linux protocol/security ASan/UBSan owner-candidate now directly executes
  that lifecycle mode; the workflow structure validator pins it.
- Production source: **UNCHANGED**. Microsoft MCS/GCC profile and UserId
  behavior: **UNCHANGED**. R8 retains CLIPRDR serializer ownership.
- Canonical local focused/full/sanitizer execution: **NOT RUN** (approved
  checkout/build root unavailable in this connector environment).
- Exact publication-SHA hosted CI/sanitizer execution: **PENDING** at
  authoring.
- Physical Microsoft client, native Admission and desktop acceptance:
  **BLOCKED / NOT RUN / unauthorized** pending R9 exact-SHA authorization.

## R8 dormant initialization/order exact-descendant qualification — 2026-10-30

- R8 implementation lineage: `aeeb318315db1634068b885f24a103ce06f4d236`,
  `95b6ba11364e5d4c3661ed6238264a54fa29300c`,
  `0665b2eab68b63d828b5ccdf68d1105bfa241463`.
- Prior external blocker: R10 incomplete-type test compile defect. Resolved by
  descendant `81633e1bfa4251a98e5dfbc9cd21853bad844599`.
- Exact workflow `41095835716`: Ubuntu protocol `124201312985` **PASS**
  Debug/Release 993/993; Windows protocol `124201312613` **PASS**
  Debug/Release 822/822; macOS protocol `124201312784` **PASS**
  Debug/Release 773/773; Windows CLANG64 producer `124201312699` **PASS**.
- The three R8 behavior CTests
  `clipboard.route-bridge-server-initialization-ordering`,
  `clipboard.route-bridge-server-initialization-generation-replacement`, and
  `clipboard.route-bridge-server-initialization-pending-write-retirement`
  **PASS** in each full protocol platform suite.
- R9 ASan/UBSan job `124201312599`: clipboard registry **104**, execution
  **104/104 PASS**; all three new R8 cases and the existing FileContents joined
  MCS-envelope regression pass under the sanitizer selection.
- No additional R8 production/test change is justified. Current `main` is a
  descendant and leaves the qualified R8 bridge/test sources unchanged.
- `kLinuxProductionClipboardActivationApproved = false`: **unchanged**.
  Physical clipboard/files/client: **NOT RUN / not authorized**.
- Benchmark: **NOT RUN / not applicable**.

## R7 typed final-authInfo exact-SHA hosted qualification — 2026-10-30

- Implementation SHA:
  `74e5fc40af280a3af1aad6527a135283fb5076fc`.
- Standalone structure guard `41095974951`: **PASS**.
- Primary workflow `41095974957`: R7 macOS portable-GUI job
  `124202365414` **PASS**; complete offscreen GUI inventory **52/52
  PASS or expected SKIP**. New
  `gui.offscreen-authinfo-typed-advanced-only-and-generation-retirement`
  **PASS**; existing
  `gui.offscreen-authinfo-failure-connection-replacement-redaction`
  **PASS**.
- The same R7 job also passes the production pre-listener no-TCC-prompt CTest,
  package integrity/framework closure, runtime PlainText source guard,
  extracted ad-hoc-signed Cocoa LaunchServices/no-listener smoke and
  owner-acceptance UI parity.
- R9 GUI Round 2 job `124209206302`: **PASS**, exact receipt
  `GUI ROUND 2 PASS: 74e5fc40af280a3af1aad6527a135283fb5076fc`.
- Ubuntu protocol, Windows protocol, Windows CLANG64, R9 security/protocol
  sanitizers, R7 macOS lifecycle/session sanitizers and owner-GUI parity jobs
  on the same SHA are **PASS**. This also demonstrates that the earlier R10
  incomplete-type lifecycle-fixture compile blocker is resolved on a
  descendant build.
- Whole primary workflow remains **FAIL** only because macOS protocol job
  `124202365497` stops compiling unrelated
  `src/server/transport/rdp_licensing.cpp:1180`: OpenSSL 4.1 deprecates
  `ASN1_STRING_length`, and `-Werror` promotes it to an error.
  No R7 source participates in that compile failure.
- Descendant `434ac8fe600e9aa6fdf7ede842d67d6f662457f3` resolves the
  R5 43/44 workflow-validator mismatch; standalone structure run
  `41096120405` is **PASS**.
- R7 code changes: **NONE** in this qualification follow-up. Local canonical
  build/full CTest: **NOT RUN**. Physical Windows App/mstsc, native desktop,
  input and clipboard: **BLOCKED / NOT RUN / unauthorized** until a common
  R9-approved candidate and genuine native R2 admission exist.

## R5 exact-SHA hosted X11 qualification — 2026-10-30

- Implementation SHA `434ac8fe600e9aa6fdf7ede842d67d6f662457f3`; structure run `41096120405`: **PASS**.
- Primary run `41096120483`, Ubuntu `124202413372`: Debug **993/993 PASS**, Release **993/993 PASS**; reentrant XDamage retirement test #893 passes in both full suites.
- R9 sanitizer `124202412993`: **PASS**; exact R5 inventory **44**, new test-name sentinel present, native X11 ASan/UBSan result **44/44 PASS**.
- R5 Linux GUI ZIP `124202413138`: **PASS**, including read-only physical-X11 precredential readiness; this is not a physical R2 lease or native acceptance.
- Global primary workflow remains non-green because macOS `124202413087` **FAILS** Debug compilation in R3 licensing: OpenSSL 4.1 deprecates `ASN1_STRING_length()` and warnings are errors. R5 Linux qualification remains valid; R3/OpenSSL is the unrelated repository-wide blocker.
- `r9-credssp-owner-candidate` is manual-dispatch-only and **SKIPPED** on push. Physical Linux seat0/input/capture remains **BLOCKED / NOT RUN / unauthorized** pending R9 exact-SHA dispatch, fresh genuine R2 same-UID unlocked-seat0 admission, and explicit owner authorization. Local canonical build and benchmark: **NOT RUN**.

## R4 current-main dependency check — R4 green, R9 blocked by macOS OpenSSL licensing compile (2026-10-30)

- Exact audited SHA: `434ac8fe600e9aa6fdf7ede842d67d6f662457f3`; primary workflow `41096120483`.
- **R4 current-main sanitizer PASS:** portable graphics **45/45**, including
  `graphics.frame-ack-deferred-revocation-generation-reset`.
- Upstream source fixes now effective: R5 44-case validator/structure gate
  **PASS**; R10 complete-type lifecycle fixture compiles in Ubuntu/sanitizer;
  Ubuntu protocol, Windows MSVC, Windows CLANG64, R9 sanitizers, Linux R2
  runtime-security, GUI/bootstrap/parity producers observed **PASS**.
- **Current R9 blocker:** macOS protocol compile fails at
  `rdp_licensing.cpp:1180`: OpenSSL 4.1 deprecates
  `ASN1_STRING_length()`; `-Werror,-Wdeprecated-declarations` makes this
  terminal. SERVER-TEST preview consequently fails and the owner-candidate
  aggregate is skipped. This is shared licensing/toolchain compatibility, not
  R4 graphics.
- R4 production behavior remains unchanged; no speculative codec fix.
  Physical native admission / first frame / ACK / resize / reconnect:
  **BLOCKED / NOT RUN** pending a green exact-SHA R9 candidate, genuine R2
  native-session authority and explicit authorization. Local build and
  benchmark: **NOT RUN**.

## R5 CI guard correction — 2026-10-30

- Parent `79c5a118ec219976273618c1596b87d5c23d8b71`; self-owned R5 structure failure on `6b9bee50dbd77145dea658a56bbf675c92ed5c5b`, run `41088602495` and descendant run `41090491580`: `missing required workflow token: r5_expected_test_count=43`. Update `scripts/validate_ci_workflow.py` to 44 and add exact reentrant-XDamage CTest sentinel; keep CI workflow selector and negative fixtures unchanged.
- Independent R10 incomplete-diagnostic-type test-header fix `81633e1bfa4251a98e5dfbc9cd21853bad844599` is retained, not overwritten. R6 delegated-authInfo **PASS** at `0143d16613152c349463aae655aa506c5c85b12a`, `native-admission=no`; physical R2/R9 remains blocked.
- Static validator/CTest name inspection **PASS**; corrected workflow structure, hosted exact-SHA full CTest, 44-case R5 native sanitizers **PENDING**. Local canonical build **NOT RUN**, physical seat0/owner input **BLOCKED / NOT RUN / unauthorized**. No benchmark.

## R4 exact-SHA graphics qualification and resolved upstream source blockers (2026-10-30)

- R4 `1371b43d1b8c0e2a88d044894c932c9ad611e6e1`:
  Ubuntu ordinary full Debug/Release **986/986 PASS**;
  macOS full Debug/Release **770/770 PASS**;
  portable graphics ASan/UBSan **45/45 PASS**, explicitly executing
  `graphics.frame-ack-deferred-revocation-generation-reset`.
  Structure guard `41085178808` **PASS**.
- R6 production-backed Microsoft offline `CredentialsVerified` is
  **PASS** at `0143d16613152c349463aae655aa506c5c85b12a`:
  MSVC full Debug/Release **822/822 PASS**, CLANG64 full Debug/Release
  **876/876 PASS**, Windows native sanitizers **60/60 PASS**.
  `native-admission=no`; no physical client proof.
- Previously failing CI structure guard 43/44 mismatch: R9 fixed
  source in `a1ef7a61afb6e1fefd9cb861fde0092d7c1f6029`;
  previous R10 incomplete-type test compile defect: R10 corrected
  source in `81633e1bfa4251a98e5dfbc9cd21853bad844599`.
  Exact descendant structure guard `41095835844` **PASS**;
  full primary `41095835716` **QUEUED**, not yet a PASS.
- Remaining **BLOCKED**: same-SHA R9 whole-project owner-candidate
  qualification, genuine R2 native-session admission and separately
  authorized physical RDPGFX CREATE/MAP/first ClearCodec/FRAME_ACK/
  resize/reconnect observations. Local canonical build/full CTest and
  benchmark **NOT RUN** in this connector. No R4 codec change proposed.

## R7 Advanced-only typed final-authInfo and generation-retirement integration — 2026-10-30

- Authoring parent: `81633e1bfa4251a98e5dfbc9cd21853bad844599`; R10 prerequisite delivered in `f85ae6ba`.
- Production R7 change: `src/gui/desktop_window.cpp` renders only
  `RuntimeAcceptedClientAuthInfoFailureReason` from the R10-projected,
  available, nonzero accepted-client and credential generation, failed CredSSP
  AuthInfo stage. `None` emits no category. No credential text, domain value,
  empty-field marker, protected payload, token material or authentication
  authority crosses the GUI; Main/Activity product classification is untouched.
- New behavior CTest:
  `gui.offscreen-authinfo-typed-advanced-only-and-generation-retirement`;
  all 7 bounded failures, no reason, missing connection/generation, wrong stage,
  verified transition and new-peer replacement. Existing
  `gui.offscreen-authinfo-failure-connection-replacement-redaction` now
  requires typed mismatch text on A and absence of that text/ID/timings on B.
- Previous R7 package/no-TCC-prompt lane at `4cb26351`: PASS in hosted macOS
  `r7-macos-portable-gui` job (workflow `41084723193`).
- R6 exact-SHA `0143d166` Windows positive CredSSP and bad-binding negative:
  PASS, `CredentialsVerified=yes`, `native-admission=no`. This is an offline
  oracle, not physical/native session acceptance.
- Latest parent `98b91f4a` standalone structure guard: FAIL unrelated
  stale R5 sanitizer sentinel `r5_expected_test_count=43` after R5 advanced
  to 44. New R8 full/sanitizer execution blocked on unrelated R10 Direct-NTLM
  lifecycle fixture incomplete-type compile error.
- Local canonical Debug/focused/full CTest/ASan/UBSan: NOT RUN (no approved
  local repo/build root). Exact publication-SHA hosted CI: PENDING. Physical
  Windows App/mstsc, native desktop, clipboard and input: NOT RUN/unauthorized.

## R10 final-authInfo CTest compilation repair — 2026-10-30

- Parent: `a0c4bb0c519d3f840979fed7fa3058dd8262d559`. Original R10 source:
  `f85ae6baaa48c110bfcbb95cb433cd0d0945c2b1`.
- Exact-source Ubuntu Debug `124168566609` and R9 sanitizer
  `124168566727` both **FAIL** at
  `test_linux_runtime_direct_ntlm_lifecycle.cpp:1836`: incomplete
  `LinuxRuntimeConnectionAcceptanceDiagnostics` at new R10 mapping
  fixture; runtime production libraries compiled.
- Repair: include the existing defining
  `server/runtime/linux_runtime_connection.h` directly in the
  existing test. No changed test assertion or production path.
- R6 Microsoft `CredentialsVerified` positive and production
  `authInfo` acceptance: **PASS** at
  `0143d16613152c349463aae655aa506c5c85b12a`; R2 verifier
  unchanged. This is offline authentication evidence only.
- Concurrent R9 `a1ef7a61afb6e1fefd9cb861fde0092d7c1f6029`
  corrects R5's 43 -> 44 CI validator count; descendant
  exact-SHA structure validation is still required.
- Local Debug/Release, full CTest and ASan/UBSan: **NOT RUN** (no
  approved checkout/build root). Repair exact-SHA hosted CI: **PENDING**.
  M1/M2 physical native/client acceptance: **BLOCKED / NOT RUN**.

## R2 current unblock / security handoff — 2026-10-30

- Positive Microsoft CredSSP is **PASS** with no R2 verifier modification:
  exact SHA `0143d16613152c349463aae655aa506c5c85b12a`,
  workflow `41088156347`, MSVC `124174758888` (ordinary Debug and
  Release **822/822 PASS** each), CLANG64 `124174758891`
  (full Debug and Release **876/876 PASS** each; native sanitizer lifetime
  **60/60 PASS**). Delegation-enabled SSPI sends final authInfo,
  `production-authinfo-empty-fields=none`,
  `production-authinfo-failure=none`, `credentials-verified=yes`;
  Microsoft bad-binding negative is still rejected, `native-admission=no`.
- The earlier `both-empty` oracle omitted `ISC_REQ_DELEGATE`. It is fixed
  by Agent 6's client-only request flag; do not loosen the standalone
  empty-credential, domain, Username or password comparison policies.
- Security composition inspected at latest source `a1ef7a61afb6e1fefd9cb861fde0092d7c1f6029`: the
  production `CredentialsVerified` stage is non-authorizing; exact connection,
  owned HYBRID TLS and credential-generation proof must precede an
  independent native broker admission/lease, and MCS/Share/native devices
  remain gated after that lease. No live/physical native test was executed.
- Other-agent qualification blockers currently observed: R5's workflow
  structure inventory still requires `r5_expected_test_count=43` although
  the R5 sanitizer inventory advanced to 44 (guard run `41090491580`
  **FAIL**); R10's lifecycle CTest fixture at its previous hosted run fails
  compilation because `LinuxRuntimeConnectionAcceptanceDiagnostics` is
  incomplete where instantiated. The current `main` protocol run
  `41090491478` is **QUEUED**, not a same-SHA PASS.
- Local canonical build/full CTest/sanitizers **NOT RUN** (GitHub-only
  environment); physical native authorization **NOT RUN / unauthorized**.
  R2 code/test changes: **NONE** in this evidence-only update. Next gate:
  R5/R9 structure reconciliation, R10 compile repair, then exact-SHA R9
  aggregate and separately authorized genuine native admission.

## R9 R5 44-case structure validator correction — 2026-10-30

- Authoring HEAD: `98b91f4a1df64f955b63a3e7c78164baffa57429`.
- At `98b91f4a1df64f955b63a3e7c78164baffa57429`, standalone structure workflow `41090491580`
  and primary `41090491478` are **FAIL**, exact message
  `missing required workflow token: r5_expected_test_count=43`.
- R5 source/CMake and `.github/workflows/ci.yml` already register,
  select and require `x11.desktop-resource-reentrant-authority-loss-damage-dispatch`
  in the R9 44-case native X11 sanitizer group. The sole structural
  validator token lagged behind. R9 updates it from 43 to 44, adds
  the exact test sentinel, and retains all denials and count checks.
- Verified 369 required workflow literals before this change: after
  unescaping Python literals, the **only missing token** was
  `r5_expected_test_count=43`. Source/registration review: PASS.
  Exact publication-SHA hosted validator: **PENDING**; local CTest: **NOT RUN**.
- R6 Windows `0143d16613152c349463aae655aa506c5c85b12a`,
  `41088156347`, MSVC `124174758888`: `CredentialsVerified=yes`,
  full exchange PASS, bad binding PASS and `COMPLETE_PASS`;
  full MSVC Debug/Release 822/822. CLANG64 `124174758891`:
  full Debug/Release 876/876 and native sanitizer 60/60 **PASS**.
- Same SHA Ubuntu job `124174759112`, R9 sanitizer job
  `124174758996` and bootstrap job `124174759394` fail to compile
  `test_linux_runtime_direct_ntlm_lifecycle.cpp:1836`:
  `LinuxRuntimeConnectionAcceptanceDiagnostics` is incomplete.
  R10 owns this regression. Do not infer same-SHA candidate eligibility
  from the Windows-only green evidence.
- Manual owner candidate remains **BLOCKED**. Skipped ordinary push is
  not PASS; no physical desktop/Windows App/mstsc testing was authorized.

## R6 Microsoft CredSSP oracle final exact-SHA qualification — 2026-10-30

- Implementation/evidence SHA:
  `0143d16613152c349463aae655aa506c5c85b12a`.
- Primary workflow: `41088156347`; standalone structure guard
  `41088156416`: **PASS**. Primary structure job `124174694486` and Windows
  PowerShell parser job `124174694119`: **PASS**.
- MSVC job `124174758888`: **PASS**. Strict Debug configure/build and R6
  native preflight pass. Focused Microsoft full exchange is **PASS** with
  TLS1.3, verified Type 3, pubKeyAuth, committed production binding, final
  authInfo, `credentials-verified=yes`, `native-admission=no`,
  `delegation-requested=yes`, terminal `delegation-returned=no`,
  `production-authinfo-failure=none`, and
  `production-authinfo-empty-fields=none`.
- The bad-server-binding parity control is **PASS** and rejects before authInfo
  with `SEC_E_INVALID_TOKEN (0x80090308)`,
  `delegation-requested=yes delegation-returned=no`. The exact Microsoft
  artifact closes `interop-matrix-final=COMPLETE_PASS` at the same source
  SHA.
- MSVC ordinary Debug project CTest: **822/822 PASS**. MSVC ordinary Release
  protocol CTest: **822/822 PASS**.
- CLANG64 job `124174758891`: **PASS**, Clang **23.1.4**. Ordinary full Debug
  CTest: **876/876 PASS**. Ordinary full Release CTest: **876/876 PASS**.
  Windows R6 sanitizer lifetime CTests: **60/60 PASS**.
  `R9 WINDOWS CLANG64 QUALIFICATION PASS` names the same implementation SHA.
- The final successful context's missing `ISC_RET_DELEGATE` remains recorded
  as `delegation-returned=no`; it is not hidden or inferred from an
  intermediate call. CredSSP credential forwarding is functionally proved by
  nonempty final authInfo accepted by production. No policy/system mutation was
  used to force the generic context capability bit.
- **Agent 2 handoff: no production verifier change is required.** R2 accepted
  the configured delegated User/Password as-is. No production authentication
  semantics were changed by Agent 6.
- Physical Windows App/mstsc and native admission: **NOT RUN**, per round
  instruction.

## R8 Round 3 hosted build evidence and external blocker — 2026-10-30

- Candidate source lineage: `aeeb318315db1634068b885f24a103ce06f4d236`
  (state machine), `95b6ba11364e5d4c3661ed6238264a54fa29300c`
  (local-generation route-authority fence), and correction
  `0665b2eab68b63d828b5ccdf68d1105bfa241463` (test type spelling).
- `41087532492` structure guard: **PASS**.
- `41087532510` workflow structure / PowerShell parser / documentation policy:
  **PASS**.
- Ubuntu job `124172757688`: `rdp-server-r8-r3-clipboard` **BUILT** and
  `test_r8_r3_clipboard_bridge` **BUILT/LINKED**. Full Debug build then
  **FAIL/BLOCKED** at unrelated
  `test_linux_runtime_direct_ntlm_lifecycle.cpp:1836` because
  `LinuxRuntimeConnectionAcceptanceDiagnostics` is incomplete.
- R9 sanitizer job `124172757534`: R8 production/test target
  **BUILT/LINKED under ASan/UBSan**; same unrelated R10 test compile failure
  prevents the sanitizer CTest phase.
- The three new R8 behavior CTests and 104-test clipboard sanitizer run are
  therefore **NOT RUN / BLOCKED**, not failed. No R8 compiler error remains in
  the observed jobs.
- Local canonical build: **NOT RUN** in this connector environment.
- Activation constant: **false / unchanged**. Physical clipboard, files and
  client: **NOT RUN / BLOCKED**.
- Next gate: qualify the unchanged R8 lineage on a descendant SHA after the R10
  fixture compiles; do not add a special CI bypass.

## R5 reentrant XDamage callback retirement — 2026-10-30

- Authoring parent: `0143d16613152c349463aae655aa506c5c85b12a`. Audited native R2 lease, R1/principal provenance and pre/post visitor checks behind R10 GraphicsReady; CredentialsVerified alone never constructs native X11.
- New production-backed ephemeral Xvfb CTest `x11.desktop-resource-reentrant-authority-loss-damage-dispatch`: genuine queued XDamage triggers revocation inside the active event callback; assert terminal event drain, no later callback/native operation, retired XCB/borrow invalidation, replacement generation isolation and fresh capture.
- R5 sanitizer inventory 43 -> 44 exact-name guarded in CI; no production code or dependencies changed.
- Private evidence validator already rejects contradictory R1/R10 timing subsets, stage ordering, first-byte/zero-count and private-unknown-field redaction. No authoritative attempt-generation scalar exists; none invented.
- Source/CTest/CI inspection **PASS**; canonical local build/CTest/Xvfb/ASan/UBSan **NOT RUN** (no approved checkout); hosted exact-publication-SHA CI **PENDING**. Physical Linux seat0/native admission **BLOCKED / NOT RUN / not authorized** pending R6, genuine R2 and R9 approval. Benchmark **NOT RUN / not applicable**.

## R6 delegation hypothesis proved; terminal context bit classified — 2026-10-30

- Evidence SHA: `671cae88da7dcb604ced089a9f21c2af9fe78597`,
  workflow `41085647004`, MSVC job `124166200509`.
- MSVC strict Debug build and R6 preflight: **PASS**.
- Positive Microsoft CredSSP receipt:
  `tls=TLS1.3 type3-verified=yes pubkeyauth=yes
  server-binding-committed=yes authinfo=yes credentials-verified=yes
  native-admission=no delegation-requested=yes delegation-returned=no
  production-authinfo-failure=none production-authinfo-empty-fields=none`.
  This proves the prior `both-empty` result was caused by omitting
  `ISC_REQ_DELEGATE`; production R2 accepts the delegated configured
  User/Password without a verifier change.
- Bad-binding parity control: **PASS**, typed `SEC_E_INVALID_TOKEN`, authInfo
  absent, `delegation-requested=yes delegation-returned=no`.
- CLANG64 Debug and Release on the same SHA both configure/build/preflight
  cleanly and their ordinary full CTest steps fail the same over-strict R6
  positive predicate requiring `delegation-returned=yes`.
- The final successful `ISC_RET_DELEGATE` bit remains a required bounded
  observation but is not the CredSSP password-forwarding acceptance predicate.
  CredSSP's request flag controls credential forwarding; generic SSPI DELEGATE
  context capability is Kerberos-specific. The functional oracle is nonempty
  delegated fields plus production `CredentialsVerified`.
- Follow-up qualification changes no production authentication code and does
  not weaken binding, required-AV, TLS, credential-source isolation, target-name
  or stack-budget controls. It removes only the unsupported terminal-bit
  success requirement while keeping `delegation-returned=yes|no` mandatory
  in the exact-SHA artifact.
- **Agent 2 handoff:** no production verifier change is required.
- Physical Windows App/mstsc and native admission: **NOT RUN**.

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
- R9's exact-SHA artifact/structure gate normalizes both delegation scalars.
  Positive qualification requires requested=yes and a present terminal yes/no
  observation, plus `production-authinfo-empty-fields=none`; bad-binding
  parity requires requested=yes/returned=no and rejection before authInfo.
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

## R2 production CredSSP verifier freeze — former Microsoft delegation blocker (historical, now resolved) — 2026-10-30

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
  `delegation-requested=yes|no` and `delegation-returned=yes|no`; the
  latter is derived only from final-success `ISC_RET_DELEGATE`. Candidate
  success requires requested=yes, a present terminal yes/no observation, empty
  fields `none`, failure `none`, raw `credentials-verified=yes`, and
  `COMPLETE_PASS`.
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
