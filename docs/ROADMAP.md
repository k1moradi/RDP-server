# RDP-server roadmap — authoritative live status

**Reconciled:** 2026-10-17 · **Shared branch:** \`main\` · **Milestones accepted:** 0/6  
**Baseline inspected before this coordination update:** \`2be8282ebb03d165f3cde7207eb9e71920e58467\`.  
**Decision:** **M1 OPEN / NOT ACCEPTED.** Hosted tests alone cannot satisfy owner-native acceptance.  
**Status vocabulary:** DONE = component delivered with specified evidence; READY = implementation ready for its next integration; BLOCKED = external/dependency gate; ACTIVE = one bounded increment in progress; NOT RUN = missing evidence.

This file is the **only active roadmap and cross-agent communication board**. It replaces the former chronological append-only progress diary. Earlier details are recoverable in Git history; exact test/CI evidence and historical failure diagnostics reside in \`docs/CODEX_VALIDATION.md\`. Do not add per-agent progress documents, repeat old reports, or append a dated section for each commit.

## Milestone gates

| Gate | Status | Acceptance condition / blocking dependency |
| --- | --- | --- |
| **M1 — build and portable/native test foundation** | **OPEN** | One nominated SHA with full hosted CI **and** full owner-local Debug configure/build/CTest receipts on Linux/X11, Windows MSYS2 CLANG64/Clang 23, and macOS **27**. All owner receipts must name that identical SHA. |
| **M2 — genuine authenticated/licensed client + Share** | **OPEN / BLOCKED** | Real R2 admission, a supported authenticated R10 licensing provider, R3 provider-correlated existing/New CAL completion, authenticated Share/finalization and real Microsoft-client acceptance. |
| **M3 — interactive Linux desktop** | **OPEN / BLOCKED** | M2 + admitted R5 X11 capture/input through R4/R3 + resize, reconnect and revocation acceptance. |
| **M4 — interactive Windows desktop** | **OPEN / BLOCKED** | M2 + admitted R6 DXGI/SendInput/WTS routing + real-client acceptance. |
| **M5 — interactive macOS desktop** | **OPEN / BLOCKED** | M2 + admitted R7 ScreenCaptureKit/input/TCC/session routing + real-client acceptance. |
| **M6 — release/service** | **OPEN / BLOCKED** | Real service/listener controls, packaging/operational hardening, measurable performance, security, soak and release acceptance. |

## P0 — M1 exact-SHA convergence

**Latest inspected shared-main baseline:** \`2be8282ebb03d165f3cde7207eb9e71920e58467\`. Primary hosted [Actions 39033398446](https://github.com/k1moradi/RDP-server/actions/runs/39033398446) and independent [structure Actions 39033398448](https://github.com/k1moradi/RDP-server/actions/runs/39033398448) are reported SUCCESS. The previous frozen candidate \`e2c1e51d22c2c33cd0de1ca40fc2bf7f45d3c5ae\` also passed hosted [Actions 39018706447](https://github.com/k1moradi/RDP-server/actions/runs/39018706447), but is **26 commits behind this inspected baseline**. Neither set of hosted evidence is owner-machine acceptance.

**Next candidate: NOT YET NOMINATED.** After this coordination commit has its own complete green hosted Actions and structure guard, R10 records its *literal* SHA and workflow link in this existing M1 section, announces the same SHA through Git, and requests a **short coordinated publication freeze**. No unrelated implementation or documentation-only receipts are published during the owner validation window. An urgent defect fix may supersede the candidate, but then **all three** owner receipts must target the new green SHA; never combine SHAs. The freeze must end after an explicit M1 decision or an owner-assigned failure, not silently remain indefinite.

| Owner-native evidence required | Status | Responsible coordination |
| --- | --- | --- |
| Linux/X11: native OS, compiler, Debug configure/build and complete CTest totals, failed/skipped/not-run | **NOT VERIFIED** | R5 + R10; R1/R2 assist on transport/security failures |
| Windows MSYS2 **CLANG64 / Clang 23**: effective compiler and exact complete Debug CTest receipt | **NOT VERIFIED** | R6 + R10; R9 verifies toolchain/selector |
| macOS **27**: \`sw_vers\`, Xcode, \`xcrun clang++\`, effective AppleClang and complete Debug CTest receipt | **NOT VERIFIED** | R7 + R10; R1 assists on native sockets |
| Exact same SHA and complete hosted CI | **OPEN** | R9 independently reviews, R10 records final M1 decision |

The owner runs the unchanged required command from \`AGENTS.md\` in the approved platform/toolchain shell, using only the persistent \`~/rdp-server/build/\`:
\`\`\`sh
cd ~/rdp-server
git switch main
git pull --ff-only origin main
git rev-parse HEAD                 # must equal R10's literal nominated SHA
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --config Debug --parallel 2
ctest --test-dir build -C Debug --output-on-failure
\`\`\`
Also record the effective native OS/compiler/configure identity, full test totals, failures and skipped/not-run counts. macOS must be **major version 27**; Windows must actually use **MSYS2 CLANG64 / Clang 23**. Never turn hosted macOS 26, synthetic Xvfb/DXGI fixtures, or an owner's informal “tests pass” into owner-native receipts. No opt-in real credentials, screen/input, service or listener is enabled by M1.

**Failure ownership:** R1 socket/TLS; R2 Kerberos/PAM/admission; R3 protocol/licensing; R4 encode/graphics; R5 Linux X11; R6 Windows native; R7 Apple native; R8 clipboard; R9 CI/registry/sanitizers; R10 runtime/config and coordination. Assign by first failing boundary rather than the commit that happened to trigger CI.

## Parallel R1–R10 work board

Each row has **one active next action**, one code owner and a concrete dependent road; edit the existing row when state changes. DONE here never implies milestone acceptance.

| Road / domain | Verified component state | Next action and dependency |
| --- | --- | --- |
| **R1 · TCP/TLS/X.224** | **READY.** Sole SSL/BIO/socket owner, bounded application reads/writes, CredSSP framing and private handoff; no new defect from P1 audit. | M1: diagnose only reproducible owner-native transport failures. M2: support R2's genuine final-CredSSP + first-MCS coalesced TLS-record acceptance; no second plaintext reader. |
| **R2 · GSS/CredSSP/native admission** | **READY / BLOCKED.** Final protected credentials → PAM/NSS/logind broker and non-forgeable Linux lease exist; synthetic denials pass. Genuine positive lease **NOT RUN**. | After M1: coordinate owner-authorized Kerberos/PAM/physical \`seat0\` X11 acceptance with R10 and R1; expose aggregate session-watch FD/event mask if real event-loop composition needs it, with denial/real-provider tests. No fabricated authorization. |
| **R3 · MCS/licensing/Share/DVC** | **READY / BLOCKED.** Move-only MAC-verified HWID + exact existing-CAL request snapshot delivered at \`c852d782\`; licensing wire groundwork exists. No authorized Share or live graphics channel. | After M1: integrate one exact R3 snapshot → R10 existing-CAL authority request/result, preserving product-policy identity, R2 generations, correlation, cancellation and R1 writer ownership. Do **not** emit valid-client status or Share without genuine authority. |
| **R4 · AVC420/x264/RDPGFX** | **READY.** \`FramebufferView\` BGRA ingress, nonzero capture epoch, native lifetime copy and IDR recovery; tests green at \`162093d3\`. | Await R3 authorized Graphics DVC/accepted-byte receipts; retain R4 frame owner through definite delivery/cancellation. No duplicate writer, encoder or throttle. |
| **R5 · Linux/X11** | **READY.** XShm/XDamage → synchronous R4 ingress with exact capture generation; tests green at \`1b7ecaec\`. | M1: own Linux/X11 native receipt and triage. M3 after M2: authorized R3 graphics/input, RandR resize and session replacement acceptance. |
| **R6 · Windows native** | **READY.** DXGI mapped BGRA → R4 borrowed frame and session/device generation/release ordering; R6 focused and CLANG64 sanitizers green at \`2be8282\`. | M1: own Windows CLANG64/Clang 23 receipt. M4 after M2: real R2 desktop lease, R3 graphics/input route, R10 WTS dispatch, monitor/reconnect revocation. |
| **R7 · macOS native** | **READY.** ScreenCaptureKit/CoreVideo BGRA lock lifetime, native display/session fencing and R4 epoch tests green at \`f037d4b\`. | M1: own actual macOS **27** receipt. M5 after M2: authorized live capture/TCC/input, display-switch and real-client evidence. |
| **R8 · CLIPRDR/files** | **READY.** Bounded FileContents and structurally verified relative hierarchy (≤64 descriptors, depth ≤16), exact index/generation; latest behavior \`441b890a\`. | Await authenticated R3 CLIPRDR route and live client. Directory materialization remains **unsupported** until independent native directory capability and race-safe handle-relative implementation; wire relative paths confer no filesystem authority. |
| **R9 · assurance/CI** | **READY.** Independent M1 audit; exact CTest registries, Clang ASan/UBSan, fuzz, Windows CLANG64 and structure policy gates are in place. | Verify chosen M1 exact-SHA hosted + three owner receipts; keep selectors synchronized with new centrally registered tests. Triage CI failures by first actual failed boundary. |
| **R10 · runtime/service/licensing/M1 lead** | **ACTIVE / BLOCKED.** Immutable security config and fail-closed existing-CAL authority at \`dc81628a\`; no production verified RD Licensing issuer and no listener. | Nominate/freeze M1 SHA and record owner matrix; then coordinate R2 runtime aggregation + R3→R10 correlation, and identify a real supportable authenticated licensing backend/infrastructure. Keep production \`NoVerifiedIssuer\` until then. |

## M2 integration order and authorization contracts

1. **R1 → R2:** one established HYBRID TLS owner, exact certificate/protocol context and GSS principal, final protected CredSSP \`authInfo\`; R2 verifies delegated password with administrator-selected real PAM and obtains fresh NSS/logind native evidence. The broker alone mints the move-only admission lease.
2. **R2 → R3:** active lease, exact user/session/policy generations and monitored revocation allow the broker-only MCS Connect Initial transition. A principal string, UID, success Boolean or synthetic lease is not authorization. Test final CredSSP frame coalesced with first MCS TPKT, unread TLS suffix, WANT-pending cancellation, real logout/session replacement.
3. **R3 → R10:** exact protected existing-CAL snapshot (CAL ≤16 KiB, 20-byte verified HWID, product/version/company/ID/scope, positive verification time, 32-byte request correlation, R2 admission/session generations). Compare the snapshot's immutable product identity to R10 policy *before* submission. R10 independently authenticates the issuing provider, trust and request digest. No peer-supplied root, generation or synthetic positive decision counts.
4. **R10 → R3:** consume a real provider result only for the same live request, generation, correlation/digest and policy. Valid-permanent, upgrade-required and denied are distinct. Real provider identity/trust, proprietary CAL semantics, expiry/product/HWID and authentic issuer infrastructure are **external M2 blockers**.
5. **R3 Share/finalization:** only after genuine licensing and cumulative R1 accepted-byte receipts may R3 advance Demand Active, Confirm Active, synchronization/control/font finalization, DRDYNVC/Graphics DVC and permitted input/clipboard routes. A joined channel, parsed CAL or encoded frame is non-authorizing.
6. **R4/R5/R6/R7/R8:** consume only current R2 admission + R3 activated/licensed session authority. Native generation replacement revokes old capture/input/output; R3 is sole application-byte writer and returns exact cumulative delivery receipts. No stale frame/input/file association can cross revocation.

**External decision needed for M2:** identify a documented, supportable, activated RD Licensing provider/backend with real issuer policy and CAL semantics; otherwise licensing intentionally remains fail-closed. Real positive Kerberos/PAM/native acceptance requires an explicitly authorized owner environment. Do not try to “unblock” either gap with a synthetic production authority.

## Shared-main Git coordination contract

- **All agents work directly on the existing \`main\`** with the canonical checkout/build root. No branches, PRs, worktrees, detached work, patches, force pushes or destructive resets. Git commits, this roadmap and the existing validation ledger are the only cross-agent handoffs; do not rely on chat reports as shared state.
- **Parallel work means independent ownership, not blind parallel writes.** Reserve the active increment's production files to its road. Cross-road integration requires the receiving owner to record the exact consumed API, lifecycle, generation and test in the relevant existing board row before writing. R1 owns TLS, R2 authorization, R3 protocol and wire writers, R4 codec, R5–R7 native owners, R8 clipboard, R9 CI assurance, R10 service/licensing composition.
- **Shared hot spots:** \`docs/ROADMAP.md\`, \`docs/CODEX_VALIDATION.md\`, \`tests/CMakeLists.txt\`, \`.github/workflows/ci.yml\`, and composition interfaces are collision-sensitive. Each implementation still publishes its own required code + dedicated registered CTest + concise edited roadmap row **atomically in one direct-main commit**. On a conflicting publication, refresh, reconcile both changes, rerun affected checks, then retry without overwrite. R9 coordinates CI selector edits; R10 coordinates only cross-road interface commitments/M1 acceptance, not every unrelated publication.
- **Optimistic publication:** start from a clean fast-forwarded \`main\`; fetch remote immediately before publishing; ensure the intended commit is based on that current head and changes do not overwrite other agents' updates. If HEAD moved, integrate current upstream changes first; never force, reset, drop another road's work or blindly restore an older complete file. Announce changes **through Git** by updating this board's existing row and citing the new commit/verification.
- **Status edit format:** road, status, exact committed source SHA, tests/CI PASS/FAIL/NOT RUN, blocker, next owner/dependency. Keep one compact row; place only genuinely new acceptance evidence in the existing M1/M2 sections. CI evidence belongs in the one validation ledger as a terse exact-SHA receipt, not mirrored paragraphs throughout the roadmap. Never write a predicted self-SHA into the same commit.
- **M1 publication freeze:** after R10 posts one nominated green candidate, all roads continue **parallel read-only review, local preflight, reproduction planning and dependency analysis**, but do not publish unrelated updates until the owner matrix is complete. Release an urgent real fix only with R10's explicit candidate reset and a fresh hosted + three-owner SHA convergence. Resume atomic independent publication after M1.
- **No work duplication:** inspect current \`main\` and CTest registrations first. If the behavior already exists and is green, report READY/blocked dependency; do not create a second seam/test/receipt commit. Every new production behavior requires one centrally registered behavior-named production-backed CTest with denial, cancellation/replay and sanitizer coverage where relevant.
- **Pruning:** delete dead code only after checking live call sites, compile variants, tests and consumers; preserve meaningful failure/security tests. Remove obsolete documentation/append-only history after consolidating its current invariant and evidence pointer; Git history is the archive. No broad code cleanup or unrelated CI rewrites during M1. R9 checks test/CI implications and the owning road performs the minimal deletion after freeze.

## Decision ledger (current only)

- **M1:** OPEN. Three owner-native exact-SHA receipts missing. Older candidate \`e2c1e51d\` is not current \`main\`.
- **M2:** OPEN. R2 real positive admission NOT RUN; R3 CAL snapshot DONE; R10 existing-CAL owner DONE but production provider unavailable; R3 authenticated licensing/Share not implemented.
- **M3–M5:** native → R4 lifetime/epoch handoffs READY; live R2/R3 publication/input/client acceptance NOT RUN.
- **Security:** HYBRID cannot jump to MCS; only one TLS/plaintext owner; R3 CAL snapshot and R4 encoded frames are non-authorizing; remote clipboard paths never grant local filesystem authority.
- **Next management check:** R10's literal M1 candidate + hosted Actions; owner Linux/X11, Windows CLANG64/Clang 23 and macOS 27 receipts; R9 independent same-SHA sign-off. Record changes by revising the above rows, not appending reports.
