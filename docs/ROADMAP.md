# RDP-server roadmap — authoritative live status

**Reconciled:** 2026-10-17 · **Shared branch:** `main` · **Milestones accepted:** 0/6  
**Baseline inspected before this coordination update:** `8f3c2f06b305eca60708867c9e50f9a6a59a79cb`.  
**Decision:** **M1 OPEN / NOT ACCEPTED.** Hosted tests alone cannot satisfy owner-native acceptance.  
**Status vocabulary:** DONE = component delivered with specified evidence; READY = implementation ready for its next integration; BLOCKED = external/dependency gate; ACTIVE = one bounded increment in progress; NOT RUN = missing evidence.

This file is the **only active roadmap and cross-agent communication board**. It replaces the former chronological append-only progress diary. Earlier details are recoverable in Git history; exact test/CI evidence and historical failure diagnostics reside in `docs/CODEX_VALIDATION.md`. Do not add per-agent progress documents, repeat old reports, or append a dated section for each commit.

## Milestone gates

| Gate | Status | Acceptance condition / blocking dependency |
| --- | --- | --- |
| **M1 — build and portable/native test foundation** | **OPEN** | One nominated SHA with full hosted CI **and** full owner-local Debug configure/build/CTest receipts on Linux/X11, Windows MSYS2 CLANG64/Clang 23, and macOS **27**. All owner receipts must name that identical SHA. |
| **M2 — genuine authenticated personal desktop + Share** | **OPEN / BLOCKED** | Real R2 authenticated native desktop admission, authenticated Share/finalization and real Windows App / Windows 11 mstsc.exe acceptance. The selected personal-desktop mode has no RD Licensing CAL gate. |
| **M3 — interactive Linux desktop** | **OPEN / BLOCKED** | M2 + admitted R5 X11 capture/input through R4/R3 + resize, reconnect and revocation acceptance. |
| **M4 — interactive Windows desktop** | **OPEN / BLOCKED** | M2 + admitted R6 DXGI/SendInput/WTS routing + real-client acceptance. |
| **M5 — interactive macOS desktop** | **OPEN / BLOCKED** | M2 + admitted R7 ScreenCaptureKit/input/TCC/session routing + real-client acceptance. |
| **M6 — release/service** | **OPEN / BLOCKED** | Real service/listener controls, packaging/operational hardening, measurable performance, security, soak and release acceptance. |

### M2 personal-desktop live-client compatibility matrix

This matrix is **separate from M1 foundation acceptance**. M1 requires the same-SHA owner build/CTest receipts below; no live-client cell substitutes for them. Each M2 client is recorded independently through negotiation, NLA, licensing, Share activation, desktop publication, input, disconnect and reconnect. A test-only licensing provider or licensing-mode fixture is never desktop authority: positive Share/desktop/input requires the real private R2 admission path, and any personal-mode implementation must retain explicit wrong-mode and malformed-license-packet denials.

| Client | Exact client version | Negotiation | NLA | Personal licensing | Share | Graphics DVC | Visible graphics | Input | Disconnect | Reconnect |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Windows 11 `mstsc.exe` | **NOT RECORDED / NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** |
| Windows App on Windows | **NOT RECORDED / NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** |
| Windows App on macOS | **NOT RECORDED / NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** | **NOT RUN** |

At starting head `8d980a202eafeefd958213f65344e955ce1b2415`, no personal-mode licensing CTest is registered on `main`; R9 therefore records that gate as **NOT PRESENT / NOT VERIFIED**, not PASS or FAIL. When that road lands, a positive licensing fixture must still terminate before Share/desktop without genuine R2 admission and must include wrong-mode plus malformed-packet denials.

This R3 publication now registers six production-backed protocol-mechanics CTests for exact Valid Client completion, presented-CAL/no-CAL personal flows, wrong-mode/malformed denial, duplicate/partial-write retirement and Share finalization ordering. They deliberately do not construct a production R2 lease; live positive advancement remains private to the broker contract in the R3 row.

**R9 P0 integration denial matrix:** primitive/offline fixtures support these
boundaries but do not accept a live desktop. Once a genuine R2/R10/R3 positive
chain exists, one production-backed integration selection must keep all rows
fail-closed.

| Boundary | Current evidence | Still required of live composition |
| --- | --- | --- |
| No R2 admission | R2 personal-runtime denial fixture | No personal licensing, Share, DVC, graphics or input |
| Wrong PersonalDesktop mode | R10 policy + R3 wrong-mode/malformed licensing | AppServer/unconfigured mode cannot select personal flow |
| Wrong TLS owner | R1/R2 HYBRID provenance and protected-transition fences | Stale/different R1 owner rejects transition/receipt |
| Stale native session | R2 generation/logind revocation fences | Logout/replacement is terminal before later progress |
| Lost Share | R3 Share denials | DVC/graphics/input unavailable after Share retirement |
| Missing Graphics DVC | R3 pre-Share DVC denial | Visible graphics impossible before exact created Graphics DVC |
| Canceled write | R1/R3 receipt cancellation; DVC generation/cancellation | Late/stale receipt cannot complete licensing, Share or DVC |
| Stale DVC ID | R3 wrong-ID + generation/cancellation denials | Retired/reused DVC identity cannot authorize graphics/input |
| Late client input | R5/R7 authority-loss no-native-post primitives | Post-R2/native/Share/DVC input never reaches native injection |

## P0 — M1 exact-SHA convergence

**Latest inspected pre-correction baseline:** `3f5c2434840181afc8d6cef2765098d7b609f946`. Independent structure Actions `39051114055` is **PASS**; primary Actions `39051114121` is **FAIL** only at the R9 direct runtime-security sanitizer registry preflight because the new registered licensing-write denial was omitted by malformed regex grouping. The correction publication is **not an M1 candidate** until its own exact-head primary and structure workflows are green. Hosted evidence is never owner-machine acceptance.

**Next candidate: NOT YET NOMINATED.** After this coordination commit has its own complete green hosted Actions and structure guard, R10 records its *literal* SHA and workflow link in this existing M1 section, announces the same SHA through Git, and requests a **short coordinated publication freeze**. No unrelated implementation or documentation-only receipts are published during the owner validation window. An urgent defect fix may supersede the candidate, but then **all three** owner receipts must target the new green SHA; never combine SHAs. The freeze must end after an explicit M1 decision or an owner-assigned failure, not silently remain indefinite.

| Owner-native evidence required | Status | Responsible coordination |
| --- | --- | --- |
| Linux/X11: native OS, compiler, Debug configure/build and complete CTest totals, failed/skipped/not-run | **NOT VERIFIED** | R5 + R10; R1/R2 assist on transport/security failures |
| Windows MSYS2 **CLANG64 / Clang 23**: effective compiler and exact complete Debug CTest receipt | **NOT VERIFIED** | R6 + R10; R9 verifies toolchain/selector |
| macOS **27**: `sw_vers`, Xcode, `xcrun clang++`, effective AppleClang and complete Debug CTest receipt | **NOT VERIFIED** | R7 + R10; R1 assists on native sockets |
| Exact same SHA and complete hosted CI | **OPEN** | R9 independently reviews, R10 records final M1 decision |

The owner runs the unchanged required command from `AGENTS.md` in the approved platform/toolchain shell, using only the persistent `~/rdp-server/build/`:
```sh
cd ~/rdp-server
git switch main
git pull --ff-only origin main
git rev-parse HEAD                 # must equal R10's literal nominated SHA
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --config Debug --parallel 2
ctest --test-dir build -C Debug --output-on-failure
```
Also record the effective native OS/compiler/configure identity, full test totals, failures and skipped/not-run counts. macOS must be **major version 27**; Windows must actually use **MSYS2 CLANG64 / Clang 23**. Never turn hosted macOS 26, synthetic Xvfb/DXGI fixtures, or an owner's informal “tests pass” into owner-native receipts. No opt-in real credentials, screen/input, service or listener is enabled by M1.

**Failure ownership:** R1 socket/TLS; R2 Kerberos/PAM/admission; R3 protocol/licensing; R4 encode/graphics; R5 Linux X11; R6 Windows native; R7 Apple native; R8 clipboard; R9 CI/registry/sanitizers; R10 runtime/config and coordination. Assign by first failing boundary rather than the commit that happened to trigger CI.

### R8 / R3 / R10 post-Share CLIPRDR handoff (P2, blocked)

**Deployment contract (R10/R9):** Human-test server bundles and runtime configuration
must expose **no clipboard or FileContents capability** until the complete
real R2 admission → R3 `ShareActivated` → R3 authenticated static-channel
route exists. A user-visible clipboard enable flag is a *preference*, never
channel authority; it cannot override absent admission, Share, confirmed join,
wrong static-channel role or missing/noncurrent generation. Do not advertise
CLIPRDR, ingest clipboard payloads, send clipboard/FileContents traffic, or
publish local text/image/file clipboard on this incomplete route. R9 must keep
a fail-closed default-off deployment/configuration test and distinguish package
presence from an activated channel. This is a required gate, **not yet verified
by a live installed bundle**; existing 81 R8 sanitizer tests only establish
clipboard component protections.

**Required R3 private visitor:** After an actual R2 policy-bound lease and
`ShareActivated`, R3 alone resolves the negotiated static `cliprdr` role,
verifies its exact confirmed MCS channel join and issues its **nonzero,
R3-owned static-channel generation**, bound to the current R3 admission,
connection/session and Share lifetime. Only R3's private, revocable visitor
may loan this tuple to R8; R8 never creates, increments, guesses or persists
channel authority. Revalidate the exact role, join, session and channel
generation and R2 lease for each inbound PDU, outbound borrow/accepted-byte
receipt, FileContents request/receipt and native clipboard publication; wrong
role, zero/stale generation, missing Share, disconnect, revocation or reconnect
retires the prior R8 source/request/stream and native-ready state *before*
replacement. A source epoch is a freshness fence, not proof of authorization.

**Transport boundary:** R3 alone handles the entire bounded MCS SendData /
negotiated static-virtual-channel chunk stream, including total-length,
FIRST/LAST ordering, permitted flags, size/overflow limits and complete
reassembly. R8 receives exactly **one complete CLIPRDR PDU** only after R3
validates that framing; R8 adds no parallel transport parser, scheduler or
chunk assembler. R3 owns the outbound static-VC/MCS/TPKT envelope, wire-slice
lifetime and mapping of R1 plaintext accepted bytes into exact full-PDU
receipts; a partial or late receipt can never commit R8 publication after
retirement.

**Post-dependency R8 increment only:** Integrate source/request/receipt and
native text, image and file publishing through that private visitor and
register behavior-named CTests for wrong `cliprdr` role, zero/stale channel
generation, missing Share, late partial receipt, disconnect/revocation,
native no-publication and reconnect/reused-number generations. Preserve the
existing descriptor maximum **64**, hierarchy depth **16**, validated
safe-relative names, exact descriptor index/generation and terminal source
epoch protection for INCR, delayed formats, native file destinations and
FileContents. Remote relative names confer **no filesystem capability**;
native directory-tree materialization remains unsupported without separately
reviewed safe handle-relative destination creation. No second clipboard
scheduler, user-selected authorization Boolean or premature OS selection.
**Next gate:** R3 publishes genuine activated static-channel route and bounded
reassembly; R2/R10 protects every application call; R8 then implements only its
owned integration and dedicated CTests. Clipboard is **not** a blocker for the
first video/input Microsoft-client test.

**R5 packaging P0 (2026-10-17):** Added a Linux test ZIP generator/installer for the actual existing `rdp-server` executable, manifest version/source SHA and file SHA-256, disabled `systemd --user` graphical-session-only unit, private example config and dedicated offline `packaging.linux-user-bundle-offline-lifecycle` CTest (install/verify/tamper/uninstall/symlink denials). **Canonical owner build/CTest NOT RUN**; hosted publication SHA **NOT RUN / pending**. R9's common SERVER-TEST path now verifies the built executable dependency closure, ABI and artifact SHA automatically; exact publication-SHA hosted evidence remains PENDING. SDK untouched. Live **M3 BLOCKED** on R10 sole admitted X11 owner + real `serve`, R3 graphics DATA receipts/input, owner-approved authentic seat0 Kerberos/PAM/NSS/logind/TLS and all three Microsoft-client receipts. See [Linux bundle contract](linux_server_test_bundle.md).

**R9 first hosted failure (2026-10-17):** Exact SHA
`4a42e7e32dcaa1db8999b3210ed426cbaf17fe6a` passed structure,
documentation, R9 sanitizer and R7 focused gates, and the new portable
SERVER-TEST contract CTest. All three ordinary Debug full CTests plus R6
CLANG64 stopped on R7's message-only negative assertion
(`architecture` vs production `unsupported bundle identity`) before
SERVER-TEST Release packaging. The assertion is corrected without changing R7
production behavior. Thus that SHA has **no server bundle acceptance receipt**;
next exact-head hosted CI must produce the three disabled previews and aggregate
same-SHA status before R9 can call the preview pipeline green.

**R9 SERVER-TEST packaging P0 (2026-10-17):** The ordinary three-OS
Release matrix now emits a distinct startup-disabled
`rdp-server-test-<version>-<platform>-<architecture>-<short-sha>` ZIP from
the actual `rdp-server` executable and never from the protocol SDK package.
Manifest/checksum/compiler/ABI/dependency/license/config/lifecycle evidence and
real extracted-binary smoke are mandatory; an aggregate job requires Linux,
Windows and macOS statuses to carry the same exact SHA. Linux consumes R5's
disabled service template and paths; R6/R7 remain extraction-only because no
authorized native serving service exists. The existing R7 protocol-only bundle
stays separate. Hosted publication-SHA acceptance is **PENDING**: `ef0feac1` produced
green Linux/macOS executable previews but Windows correctly failed before
artifact creation while R9 tightened the OS-owned runtime dependency boundary.
RUNNABLE publishing remains blocked on R10 startup plus exact-head green CI and
explicit owner acceptance. M1 owner-native and M2 three-client receipts remain separate.

## Parallel R1–R10 work board

Each row has **one active next action**, one code owner and a concrete dependent road; edit the existing row when state changes. DONE here never implies milestone acceptance.

| Road / domain | Verified component state | Next action and dependency |
| --- | --- | --- |
| **R1 · TCP/TLS/X.224** | **READY / post-admission R1 intake composed by R10; BLOCKED on genuine R2 live admission evidence.** Buffered TLS readiness remains exactly `2d295603`: `tlsApplicationReadReady()` queries only processed plaintext in the exact R1-owned SSL, preserves pending write/read-WANT_WRITE retry direction and consumes nothing. On exact SHA `7ac63a25`, Ubuntu/GCC passes **617/617 Debug + 617/617 Release**; `transport.tcp-owned-buffered-tls-credssp-mcs-readiness` (#168), `transport.tcp-owned-tls-application-cancellation` (#181) and `runtime.linux-connection-pre-admission-dispatch` (#375) pass in both. R9 ASan/UBSan is **93/93 PASS** for the bounded R1/R3 selector including the buffered case and **15/15 PASS** for direct Linux runtime-security at that SHA; later R2/R9 commits add denial-only native desktop evidence without changing R1. No second R1 defect found. | Keep all TLS application reads/writes and accepted-byte accounting in R1. R10 now owns the bounded post-admission TPKT route through this exact R1 application-I/O boundary; live positive final-CredSSP + first-MCS remains **NOT RUN / BLOCKED** only on an owner-authorized genuine R2 native lease. Never revive the legacy competing reader or add an R3 SSL reader/queue/scheduler. Maintain exact-build Microsoft-client capture evidence; current R1 policy selects `PROTOCOL_HYBRID`, not HYBRID_EX. |
| **R2 · GSS/CredSSP/native admission** | **ACTIVE / production build + preflight increment authored; real-host positive BLOCKED.** Linux remains the sole genuine positive issuer: final CredSSP/GSS identity + exact R1 TLS owner + PAM/NSS/logind physical-session evidence produce the move-only lease. R2 binds the exact immutable PersonalDesktop policy object across Server License Request, client licensing, Valid Client, Share and post-Share application gates. With R3 Graphics CREATE/CAPS now available, R2 also wraps its private Graphics DVC begin, pending-write, accepted-byte receipt and client-TPKT transitions; every call reuses the same current TLS/GSS/native evidence and admission/session generation checks. Value-equivalent policy replacement, logout/logind change, disconnect, stale generations and late receipts are terminal. | **R10 handoff:** continue using the existing policy-bound licensing/Valid Client/Share APIs, and after genuine Share activation use only R2's new Graphics DVC wrappers around R3—never call R3's private positive transitions directly. R1 remains the sole TLS application-I/O owner and exact accepted plaintext count source. Linux real Kerberos/PAM/X11 `seat0` positive acceptance remains **NOT RUN** pending an owner-authorized host; Windows/macOS evidence readers remain non-authorizing until genuine credential-bound R2 leases exist. |
| **R3 · MCS/licensing/Share/DVC** | **DATA PUBLICATION IMPLEMENTED / HOSTED VALIDATION PENDING; live desktop remains owner-host gated.** This increment adds bounded MS-RDPEDYC `DATA_FIRST`/`DATA` server fragmentation plus client reassembly to the sole Graphics DVC owner, uses the server-advertised static-VC chunk bound only when both endpoints carry the optional field (otherwise 1600), retains the move-only R4 `GfxAvc420SegmentedFrame`, and builds one ordered gap-free/non-overlapping `wireBytes()` → outer plaintext map with TPKT/X.224/MCS/static-VC/DVC headers accounted separately. R1 plaintext accepted-byte receipts advance only through the existing R2 broker; exact full mapped coverage completes R4, conclusive zero publication can cancel, and stale receipts, mapping failures or terminal positive/uncertain partial publication abort through R3 teardown. ClearCodec requires confirmed Graphics caps; AVC420 additionally requires the negotiated AVC420 flag. The R3 Graphics sanitizer inventory expands **6→15** with dedicated zero/full/partial/stale/share-loss and malformed/wrong-channel/reassembly cases; offline tests mint no R2 lease. Canonical owner-local build/CTest is **NOT RUN** in this connector environment. | **Next R3 gate after hosted green:** finish the narrow decoded keyboard/pointer post-Share route with fresh R2 permission, then publish the separate CLIPRDR role/channel-generation API for R8. R10 now has a public prepared-frame start/cancel composition surface and continues to submit every R3 record only through R1. Genuine Kerberos/PAM/NSS/logind/X11 `seat0` + Microsoft-client visible-frame acceptance remains **NOT RUN / BLOCKED** on explicit owner authorization, not on offline DATA implementation. |
| **R4 · AVC420/x264/RDPGFX** | **READY / R3 DATA integration candidate now authored; hosted verification pending.** R4 retains mandatory ClearCodec fallback plus explicitly negotiated AVC420, owns the move-only segmented frame and delivery receipt, and advances codec/frame state only on exact complete delivery. No codec authority comes from DVC CREATE alone. | Consume the new R3 frame-publication boundary only after its hosted CTest/sanitizer matrix is green. R3 must remain the sole DVC/static-VC/MCS/TPKT mapper; R4 continues to own encoding, presentation receipt and FRAME_ACKNOWLEDGE semantics. Real Microsoft-client visibility remains **NOT RUN** until genuine R2 admission and owner-authorized live desktop testing. |
| **R5 · Linux/X11** | **READY / BLOCKED on R10/R3 live composition.** Existing XShm/XDamage → synchronous R4 ingress and exact RandR geometry-generation fencing remain unchanged from `286b71c6b953600c97157f29d2eb7f3fbc15842b`: stale decoded pointer/keyboard events cannot cross a replacement, and native generation equality is freshness only. Audit on green shared head `d93f1a0e8b31a43401e3b0cfae5bd439caae7664` found one concrete teardown defect: an admission/generation/permission denial could call graceful `X11InputController::disconnect()` after R2/R3 revocation and emit held-key/button release XTEST events with no remaining input permission. This increment separates graceful/RandR release from terminal `retireWithoutNativeInput()`, adds aggregate `retireAfterAuthorizationLoss()`, and routes every pre-injection freshness/admission/permission denial through no-post retirement. Dedicated `x11.input-native-authority-retirement-no-native-post` uses only ephemeral Xvfb and expands the anchored R5 sanitizer selector **37→38**; canonical owner-local build/live desktop are **NOT RUN**, publication-SHA hosted CI **PENDING**. R2 `466e73ec` remains the sole admitted display/session visitor; `483be256` adds protected PersonalDesktop/Share/application-ready wrappers and R10 `5f0c1683` adds admitted first-MCS framing through R1 TLS, but neither constructs an X11 owner. | **M3 contract:** R10 must construct exactly one fresh `X11DesktopResources` inside `visitNativeDesktopSelection()` from the R2-observed display, never configured `DISPLAY`, Xvfb identity, client data or a scalar generation. R10 removes the borrowed logind registration before revocation/dispatch; after authority loss R5 uses no-post input retirement before XI2/Damage/XShm/cursor/XCB teardown. Synchronous XShm→R4 work may finish only inside its borrow, but any prepared unwritten R4 frame becomes non-publishable on R2/R3/native revocation and must be canceled by the future composed owner. Every decoded input still needs current R2 + R3 `kConsoleInputPermission` and the captured exact R5 generation immediately before XTEST. R3 still owes authenticated post-`ShareActivated` DRDYNVC/Graphics publication + decoded input routing, and R10 still owes the serialized connection/desktop composition. |
| **R6 · Windows native** | **ACTIVE / BLOCKED on genuine Windows admission.** Green baseline `67506c6e43ff0ed76b00e757ad07db8fab370727`, primary Actions `39045944788`, has MSYS2 CLANG64 / Clang 23.1.3 R6 **58/58 PASS Debug + 58/58 PASS Release + 58/58 ASan/UBSan**; all three `windows.capture-r4-*` cases pass in each selection. DXGI/R4 ownership remains `Acquire → Map → Consume → Unmap → ReleaseFrame` with exact pre/post `{session, device}` fencing, stale prepared-output cancellation, deferred child-before-parent COM teardown and the existing serialized WTS retirement helper. Audit found one independent future-composition gap: graceful input `cancel()` may release held state when native freshness is still current even though upstream R2/R3 input authority has ended. This increment adds revocation-only `retireWithoutNativeInput()` plus `windows.input-sendinput-authority-retirement-no-native-post`; it grants no authority and raises the current R6 selector to **59**. Publication-SHA hosted CI **PENDING**; owner-local build/live desktop **NOT RUN**. | **Positive R6 consumption remains blocked:** R2's token/LSA/WTS reader is observation-only until a genuine Windows SSPI/CredSSP owner binds the authenticated SID to the active physical-console WTS session, exact logon LUID/time and a private revocable admission/session generation. R10 owns serialized WTS registration/delivery and continues to call `retireWindowsNativeConsumersOnSessionChange(...)`, with `completeDeferredClose()` only after the active capture callback returns. Upstream R2/R3 authority loss with unchanged WTS/native freshness must stop routing first, call the no-native-input retirement path, retire capture/cancel any unwritten R4 owner, then complete deferred close at the safe point. R3's created Graphics DVC remains non-authorizing by itself: current same-connection R2 + R3 application/Graphics/input authority must be revalidated at frame publication and immediately before input dispatch. Reconnect or numeric WTS-session reuse requires a fresh R2 lease and fresh R6 owner/generation; no scalar WTS/R6 value authorizes. |
| **R7 · macOS native** | **PACKAGING READY / native serving BLOCKED on genuine admission and R10/R3 composition.** Exact head `9a2d09968e741d13bc1c5e76753ecaf1be7557ef` is green: primary Actions `39066363832`, structure Actions `39066363884`, hosted macOS **546/546 Debug + 546/546 Release**, focused R7 **21/21 Debug + 21/21 Release**, authority-loss input sanitizer **2/2**, protocol test-bundle packaging PASS and startup-disabled `rdp-server-test-0.1.0-macos-arm64-9a2d09968e74` SERVER-TEST artifact PASS. R9 therefore resolved R7's prior package/CI blocker. This R7 increment adds a bundled, offline-only per-user LaunchAgent renderer/validator with fixed user path, Aqua session, `RunAtLoad=false`, `KeepAlive=false`, strict key/path denial and no registration/start/TCC/network/capture/input side effects; its publication-SHA hosted evidence is **PENDING**. | **Native-serving blockers remain:** R2 still exposes only read-only macOS session evidence and no genuine credential-bound UID lease; R3 still explicitly lacks Graphics DVC `DATA_FIRST/DATA` publication; R10 still has no macOS AppKit runtime/session aggregate. Until all three land, manual LaunchAgent `kickstart` reaches only the current fail-closed `serve` command, Screen Recording/Accessibility remain prerequisite observations only, and M5 owner-macOS-27/live-client acceptance is **NOT RUN**. |
| **R8 · CLIPRDR/files** | **READY / BLOCKED; safe-disabled for human tests.** Bounded FileContents and the verified relative hierarchy (≤64 descriptors, depth ≤16, exact index/generation; hierarchy evidence at `441b890a`) remain unchanged. R3 retirement clears request/stream/native-ready state, while the monotonic source epoch now fences native file destinations plus Windows/macOS/X11 publication across disconnect and same-number generation reuse. Dedicated regressions cover stale delayed/INCR callbacks, immediate pasteboard retirement and completed-file source-epoch revocation. | R3 must own the one genuinely licensed + Share-activated CLIPRDR route and revalidate current R2 authority plus exact R3 session/channel generations before every R8 ingress, write/receipt, FileContents operation and native publication; any mismatch retires R8 before replacement. Native owners that survive retirement must correlate the R8 source epoch as freshness only, never authority. Live client remains blocked on R3 licensing/Share. Directory-tree materialization remains **unsupported** without separately reviewed native directory capability + race-safe handle-relative creation; remote relative names never grant filesystem authority. |
| **R9 · assurance/CI** | **ACTIVE / P0 SERVER-TEST preview: Linux + macOS exact-head smoke PASS at `ef0feac1`; Windows dependency-boundary correction PENDING.** The ordinary Linux/GCC, macOS/Clang and Windows/MSVC Release matrix now packages the real `rdp-server` executable as a distinct startup-disabled SERVER-TEST family after full CTest, records exact SHA/compiler/ABI/dependency/license/internal+outer SHA-256 evidence, and smoke-checks ABI, `--version`, `--help`, config validation, unconfigured `serve` refusal, install-time no-listener, idempotent extraction/removal, no autostart and secret markers. A cross-platform status job requires all three artifacts at the same SHA. The existing protocol SDK/release and R7 protocol-only bundle remain separate. Sanitizer inventories remain R10 **28**, R3 Graphics **6**, R4 portable **42**, ClearCodec **4**, R5 **38**, R6 **59**, R7 authority-loss input **2**, R8 clipboard **81**. | **Next action:** require the publication SHA's structure/full/sanitizer/package jobs to go green and investigate the exact first failure if any; do not create a RUNNABLE SERVER-TEST prerelease until R10 secure startup exists and the owner explicitly accepts it. Keep M1 owner-native same-SHA receipts and M2 three-client human acceptance separate from hosted preview CI; package presence never proves R2 admission or deployment. |
| **R10 · runtime/service/licensing/M1 lead** | **ACTIVE / R3 prepared-frame composition authored; hosted validation pending.** Existing control negotiation remains unchanged. `startPersonalDesktopGraphicsFramePublication(...)` transfers one prepared move-only R4 frame through the current R2 authorization gate into R3, while `advancePersonalDesktopGraphicsDynamicVirtualChannel(...)` drives every DATA record through R1 and returns to `Ready` only after R3 reports exact delivery. `cancelUnwrittenPersonalDesktopGraphicsFrame(...)` is available only when R3 proves zero accepted outer plaintext. Terminal R1 close/error/revocation still closes R3, which aborts any active frame. | Hosted publication-SHA CI is the immediate offline gate. Secure listener/lifecycle work can proceed independently. Genuine Linux admission/client acceptance remains **NOT RUN** until explicit owner authorization for Kerberos/CredSSP + PAM/NSS + logind physical-X11 `seat0`; R10 must not fabricate a lease for positive frame tests. |

## M2 integration order and authorization contracts

1. **R1 → R2:** one established HYBRID TLS owner, exact certificate/protocol context and GSS principal, final protected CredSSP `authInfo`; R2 verifies the authenticated account against fresh native interactive-console evidence and alone mints the revocable admission lifetime.
2. **R2 → R3:** active lease, exact user/session/policy generations and monitored revocation allow protected MCS/licensing/Share transitions. Logout, session replacement or owner mismatch is terminal; principal strings, UID/SID values and success Booleans never authorize.
3. **R10 product policy:** service composition selects exactly one immutable mode. `AppServerIssuerBacked` keeps the existing `RuntimeLicensingAuthority::NoVerifiedIssuer` fail-closed path unless a supported provider is separately configured. `PersonalDesktop` is a distinct MS-RDPELE personal-terminal-server mode: no CAL validation/issuance is requested, at most one interactive console session is claimed per connection, and native-session revocation remains mandatory. Policy selection alone grants no R2/R3/native authority.
4. **R2 → R3 personal path:** with the same genuine lease and exact R1 owner freshly reauthorized, R2 consumes R10's `PersonalDesktop` policy and alone invokes R3's private selector before Server License Request. R3 then owns the already-published Valid Client and Share state: after a structurally valid client licensing response it emits `STATUS_VALID_CLIENT` / `ST_NO_TRANSITION`, does not validate a presented CAL, and reaches `ShareActivated` only after exact accepted-byte and client-activation ordering.
5. **R3 application publication:** only current R2 admission plus exact completed R3 personal licensing/activation may expose DRDYNVC/Graphics/input/clipboard routes. App-server mode continues to require genuine issuer-backed licensing instead; neither mode can use a test provider or a policy object as desktop authority.
6. **R10 controlled listener seam:** personal mode may explicitly enable only an exact loopback transport candidate (127.0.0.1 or ::1) and a nonzero port. This policy opens no socket and accepts no client. A real bounded listener remains gated on published non-forgeable R2 admission and R3 activated-session capabilities and explicit owner authorization; no public bind, firewall change or live desktop action is implied.
7. **R4/R5/R6/R7/R8:** consume only current R2 admission + R3 activated session authority. Native generation replacement revokes old capture/input/output; no stale frame/input/file association crosses revocation.

**R7 macOS private R2/R10 authority contract (2026-10-17):** R2 is the only
component allowed to turn authenticated-user proof into native desktop
admission. Its macOS path must authenticate the local account through the
selected real credential mechanism, resolve the immutable local UID, then
compare it with a fresh `MacNativeSessionEvidence` observation:
`consoleUserId == authenticatedUserId == auditUserId == geteuid()`, nonzero
audit session ID, nonzero Security session ID, `sessionHasGraphicAccess`, and
neither `sessionIsRemote` nor `sessionIsRoot`. That observation is evidence,
not the capability. The private R2 lifetime must also carry exact
admission/session generations and revoke on credential/session loss or any
fresh evidence mismatch. No caller UID, Boolean, generation, AppKit/CGSession
fact or TCC status can recreate it.

R10 may compose R7 only while that current R2 lifetime and the same connection's
R3 PersonalDesktop `ShareActivated` authority are both current. R10 is the
sole serializer for `NativeSessionChangeWatch::startNative()/stop()` on a
running AppKit main loop. It derives the R7 target UID only from R2, refreshes
native geometry, owns the revocation-only `MacDesktopSessionGuard`, and checks
Screen Recording or Accessibility only as the operation-specific final OS
prerequisite. The native ScreenCaptureKit backend and Quartz posting callback
remain private/unexposed until this composition exists.

Reauthorize immediately before capture prepare/start, before accepting a
prepared R4 frame for later R3 publication, and immediately before every Quartz
command batch. R2 or R3 loss is terminal even if geometry/session/TCC still
look current: R10 first closes the authority gate, calls
`MacInputController::retireWithoutNativeInput()`, closes the one-shot capture
owner, treats late callbacks as non-publishable, cancels an exact prepared but
unpublished R4 owner when R7 returns `RetireStream`, and retires the AppKit
watch only after R7 owners are terminal. A native event already accepted when
revocation races its callback cannot be retracted, but the outer input
operation must fail and no later release or input event may be posted. Fresh
access requires a new R2 lifetime, fresh R3 Share authority and fresh R7
geometry/session binding.


**R2 production startup-security increment (2026-10-17):** on reconciled parent `d8a5cbd386ae488ec265efe89d556d7d22085a39`, Linux runtime security gains explicit production build option `RDP_SERVER_ENABLE_LINUX_RUNTIME_SECURITY`, independent of `TEST_*` and `BUILD_TESTING`. Enabling it requires Linux GSSAPI/Kerberos, PAM and libsystemd at configure time; missing dependencies fail closed. The R2-owned `preflightPersonalDesktopAdmission()` reports only non-secret GSS/PAM/PersonalDesktop/native-evidence facts and can never report authenticated admission. Dedicated `runtime.linux-security-personal-desktop-preflight-denials` covers unconfigured, wrong-mode and non-admitted native evidence without fabricating seat0 or a lease. Canonical local build/CTest and owner-authorized live Kerberos/PAM/NSS/logind X11 seat0 are **NOT RUN** in this connector environment. R10 still owns consumption in the future `serve` path; R3 Graphics DATA remains a separate publication blocker.

**R10 R2/R3 composition increment (2026-10-17):** consumed R2 `bb25af3` and R3 `6e2a84a` on reconciled parent `8f3c2f06b305eca60708867c9e50f9a6a59a79cb`. Product/version/company/product-ID/scope equality is checked against the service `RuntimeLicensingContext` identity before `beginExistingCalValidation()`; R3's borrow is never retained. The connection binding retains the 32-byte correlation and exact R2 admission/session generations, while the authority retains protected HWID, verification time, authenticated provider generation/fingerprint and request digest. Generation replacement cancels a pending request before provider poll; duplicate begin, stale result/retirement, unavailable authority and reconnect reuse fail closed. Linux composition reauthorizes through R2 before begin/poll/result use, cancels/retire authority state before R3/R2 teardown, and cannot translate a test-only decision into Share. Dedicated CTests are `runtime.licensing-existing-cal-connection-unavailable-denial`, `runtime.licensing-existing-cal-connection-cross-generation-cancellation`, `runtime.linux-connection-existing-cal-unadmitted-denial`, and `runtime.linux-connection-native-monitor-registration-denials`; the existing R2 borrow denial is also in the direct sanitizer selection. Canonical local `~/rdp-server/build/`: **NOT RUN** in this connector environment; no second build root was created. Initial publication `b35fe8cc2a1da47f917f57e1812ee459d73e03c4`: **CI FAILURE** before compile because the R10 workflow-edit authoring step duplicated a YAML job key; Actions 39040560442 (structure guard) and 39040559343 (primary workflow) failed. The correction rebuilds the intended selector edits from reconciled parent workflow content; production composition code is unchanged. Corrective descendant `b18ca13303c025e315b33787edbe5cd842a7777c`: structure/documentation gates **PASS**, but Ubuntu/macOS Debug compile failed at R3's new existing-CAL fixture because `McsSessionLifecycleTestAccess` bypassed its already-defined friend helper and called two private request methods directly. This test-only recovery routes those calls through `RdpExistingClientCalAuthorityRequestTestAccess`; production R3/R10 code is unchanged. Next descendant exact-SHA CI: **PENDING**. Next gate is CI/owner evidence plus the external issuer decision below.

**R10 app-server provider feasibility decision (2026-10-17; app-server mode only):** **BLOCKED — project-owner direction required for app-server deployments.** Microsoft [MS-RDPELE] specifies the *client ↔ terminal-server* license PDUs, not the separate *Session Host ↔ license-server* RPC. The architecture describes that RPC for new/upgrade CAL issuance, but this investigation has not identified a documented, supported, authenticated API contract that lets this independent C++23 app-server validate presented CALs and issue/upgrade licenses through Microsoft RD Licensing as an authorized non-Windows Session Host. Windows RD Licensing WMI/PowerShell management/reporting interfaces do not establish such an issuance/verification API. Accordingly **no provider is chosen** for `AppServerIssuerBacked`; that production authority stays `NoVerifiedIssuer`, with no issuer-backed positive completion. The separately approved `PersonalDesktop` mode follows MS-RDPELE personal-terminal-server semantics and does not treat itself as an issuer/provider fallback. The owner must either (a) provide vendor-confirmed interoperability/support terms and an authenticated issuer API for independent app-server use, or (b) explicitly approve a product-scope/licensing-design change before implementing a different compliant provider.

**Required provider contract if supported:** mutual authentication to a specifically pinned issuer identity (Windows/domain credential or service identity and protected transport as documented by its vendor), immutable trust roots/policy and per-request provider-generation binding; explicit signature-chain issuer verification, exact `PRODUCT_INFO` version/company/product ID plus scope, permanent/temporary/upgrade status, expiry including the seven-day upgrade threshold, MAC-verified 20-byte HWID and device/user CAL mode. The R10 authority must bind the provider's verified decision to the 32-byte R3 correlation, digest, positive verification timestamp and live R2 admission/session generations. The owner must supply an activated Windows RD Licensing role, installed and appropriately scoped CAL key packs, supported access credentials and licensing mode, reachable network/domain or workgroup infrastructure, and permission/confirmation from Microsoft or the provider for this app-server integration. An activated licensing server by itself is not a verified R10 backend. MS-RDPELE 1.3.1/3.1.5.1 and Microsoft RD Licensing activation/session-host guidance are the normative references. **External blocker:** supported non-Windows Session Host issuance + existing-CAL validation authority interface and authorization to use it.

**M1 evidence reconciliation:** Repository receipts currently enumerate hosted Actions, not a complete single-SHA set of owner-local Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 configure/build/CTest records. Informal owner-reported passes may be valid but cannot establish exact-SHA acceptance without SHA, effective OS/toolchain, configure/build outcomes, complete CTest totals and failed/skipped/not-run counts. **M1 remains OPEN, not a reason to halt unrelated M2 implementation**; request only missing receipt fields, not unnecessary reruns.

**Current personal-desktop M2 dependencies:** R2 must publish protected wrappers that consume R10's immutable `PersonalDesktop` policy only with a genuine live admission lease and exact R1 owner, then invoke R3's private personal selector/Valid Client/Share transitions. Linux real Kerberos/PAM/logind admission remains owner-environment dependent; Windows/macOS still need genuine R2 authenticated native-admission leases. The app-server issuer blocker remains applicable only to `AppServerIssuerBacked`. No synthetic authority or public listener is permitted.

## Shared-main Git coordination contract

- **All agents work directly on the existing `main`** with the canonical checkout/build root. No branches, PRs, worktrees, detached work, patches, force pushes or destructive resets. Git commits, this roadmap and the existing validation ledger are the only cross-agent handoffs; do not rely on chat reports as shared state.
- **Parallel work means independent ownership, not blind parallel writes.** Reserve the active increment's production files to its road. Cross-road integration requires the receiving owner to record the exact consumed API, lifecycle, generation and test in the relevant existing board row before writing. R1 owns TLS, R2 authorization, R3 protocol and wire writers, R4 codec, R5–R7 native owners, R8 clipboard, R9 CI assurance, R10 service/licensing composition.
- **Shared hot spots:** `docs/ROADMAP.md`, `docs/CODEX_VALIDATION.md`, `tests/CMakeLists.txt`, `.github/workflows/ci.yml`, and composition interfaces are collision-sensitive. Each implementation still publishes its own required code + dedicated registered CTest + concise edited roadmap row **atomically in one direct-main commit**. On a conflicting publication, refresh, reconcile both changes, rerun affected checks, then retry without overwrite. R9 coordinates CI selector edits; R10 coordinates only cross-road interface commitments/M1 acceptance, not every unrelated publication.
- **Optimistic publication:** start from a clean fast-forwarded `main`; fetch remote immediately before publishing; ensure the intended commit is based on that current head and changes do not overwrite other agents' updates. If HEAD moved, integrate current upstream changes first; never force, reset, drop another road's work or blindly restore an older complete file. Announce changes **through Git** by updating this board's existing row and citing the new commit/verification.
- **Status edit format:** road, status, exact committed source SHA, tests/CI PASS/FAIL/NOT RUN, blocker, next owner/dependency. Keep one compact row; place only genuinely new acceptance evidence in the existing M1/M2 sections. CI evidence belongs in the one validation ledger as a terse exact-SHA receipt, not mirrored paragraphs throughout the roadmap. Never write a predicted self-SHA into the same commit.
- **M1 publication freeze:** after R10 posts one nominated green candidate, all roads continue **parallel read-only review, local preflight, reproduction planning and dependency analysis**, but do not publish unrelated updates until the owner matrix is complete. Release an urgent real fix only with R10's explicit candidate reset and a fresh hosted + three-owner SHA convergence. Resume atomic independent publication after M1.
- **No work duplication:** inspect current `main` and CTest registrations first. If the behavior already exists and is green, report READY/blocked dependency; do not create a second seam/test/receipt commit. Every new production behavior requires one centrally registered behavior-named production-backed CTest with denial, cancellation/replay and sanitizer coverage where relevant.
- **Pruning:** delete dead code only after checking live call sites, compile variants, tests and consumers; preserve meaningful failure/security tests. Remove obsolete documentation/append-only history after consolidating its current invariant and evidence pointer; Git history is the archive. No broad code cleanup or unrelated CI rewrites during M1. R9 checks test/CI implications and the owning road performs the minimal deletion after freeze.

## Decision ledger (current only)

- **M1:** OPEN. Three owner-native exact-SHA receipts missing. Older candidate `e2c1e51d` is not current `main`.
- **M2:** OPEN. R2 real positive admission NOT RUN; R3 CAL snapshot DONE; R10 existing-CAL owner DONE but production provider unavailable; R3 authenticated licensing/Share not implemented.
- **M3–M5:** native → R4 lifetime/epoch handoffs READY; live R2/R3 publication/input/client acceptance NOT RUN.
- **Security:** HYBRID cannot jump to MCS; only one TLS/plaintext owner; R3 CAL snapshot and R4 encoded frames are non-authorizing; remote clipboard paths never grant local filesystem authority.
- **Next management check:** R10's literal M1 candidate + hosted Actions; owner Linux/X11, Windows CLANG64/Clang 23 and macOS 27 receipts; R9 independent same-SHA sign-off. Record changes by revising the above rows, not appending reports.

### Personal-desktop licensing decision (2026-10-17)

The selected Windows App / Windows 11 `mstsc.exe` personal-desktop mode does
not require an RD Licensing CAL decision and must not wait on the existing
CAL-authority work. Existing licensing code remains isolated for modes that
need it; it is not an authentication substitute. R2 authenticated identity +
native OS admission remains mandatory before any R3 Share, graphics, input or
clipboard authority.
