## R9 Windows sanitizer selector cardinality correction after R6 target-selection test (2026-10-22)

Exact product-main candidate `befc9577ea7403c159f2dce720649ca0c3e985c6`, primary Actions run
`39748272928`, is **REJECTED** for qualification because mandatory
`r6-windows-clang23` job `119722473795` fails in the sanitizer preflight.
The ordinary Windows/MSVC lane passes, the CLANG64 full Debug/Release build and
all 750 ordinary CTests pass, the extracted portable GUI smoke passes, and PE
closure passes. The failing preflight enumerates **60** tests under
`^windows\.(geometry|capture|cursor|input)-` but still asserts the historical
cardinality **59**, so sanitizer execution never begins.

R6 intentionally added
`windows.geometry-single-monitor-native-target-selection` with its gated
native-target construction. R9 therefore updates the qualification invariant to
require that exact new test by name and to require cardinality 60. No test is
removed, no selector is narrowed, and no Windows/MSVC, CLANG64, sanitizer,
packaging, PE-closure, CLEAN or runtime coverage is weakened.

This publication creates a replacement exact product-main candidate requiring a
fresh complete ordinary-hosted PASS. Linux FIRST remains independently frozen
at `8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`. CLEAN remains **NOT RUN**
pending a real clean-Windows receipt; verifier-accepted owner-native evidence is
**MANUAL CLEAN PASS**, never automated CI PASS.

## R9 Windows PE closure correction for documented MSCMS system import (2026-10-21)

Exact candidate `02f039fdfd2d9298f4b2fb0f8d8cc1d087d7c64b`, primary Actions run
`39727607434`, is **REJECTED** despite every completed ordinary lane except
R6 packaging being green. The mandatory `r6-windows-clang23` job
`119655064357` passed Debug and Release CLANG64 compilation/full CTest, the
R10 private-fixture preflights, and the unsupported-password GUI CTest, then
failed recursive PE closure because current Qt `plugins/platforms/qwindows.dll`
imports `mscms.dll`.

This is an OS-system dependency classification correction, not a coverage
waiver. Microsoft Win32 ICM documentation lists `Mscms.dll` as the DLL for
the Windows color-management APIs. R9 adds only that exact DLL name to the
existing finite system allowlist and extends the portable PE-closure regression
to require it to be accepted while non-system runtimes remain rejected. The
recursive `llvm-objdump` closure scan, application-local dependency
requirements, Windows CLANG64 build/CTest and extracted-GUI smoke remain
unchanged.

Shared-main advanced to R6 parent `4de56b15a2a28294086db71dba1b8bf0ee8ea9f7` while the failed run was
completing; that R6 commit does not modify the PE verifier. This R9 publication
therefore rebases the narrow correction on current main and creates a new exact
product-main candidate requiring a fresh complete ordinary-hosted PASS. Linux
FIRST remains independently frozen at
`8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`. CLEAN remains **NOT RUN**;
manual owner-native evidence, when verifier-accepted, is labeled
**MANUAL CLEAN PASS**, never automated CI PASS.

## R9 exact parser-extent correction and current qualification candidate (2026-10-21)

Exact product-main parent `25415342b0f190241988ba0895855faebc1d7a00`, primary Actions run
`39727420489`, is **REJECTED** for qualification because ordinary hosted
`r9-windows-powershell-parser` job `119654435275` fails on
`scripts/clean_windows_portable_gui.ps1` at source lines 16-17. The hosted
PowerShell 5.1 parser reports a missing closing parenthesis before the nested
`Join-Path` expression and then treats that nested opening/closing parenthesis
as unexpected tokens. This is the same defect independently surfaced by the
ordinary Windows clean-release structure test; Windows coverage is not weakened.

The correction replaces only that multi-line compound command expression with
explicit intermediate `scriptDirectory` and `smokeScriptCandidate` variables,
then resolves the same exact smoke-script path. Receipt contents, exact-source
and ZIP hashing, non-admin/Explorer checks, clean PATH/install-root checks,
launch/ordinary-close/relaunch, socket observations, and
firewall/service/TermService/RDP-policy invariance are unchanged.

This publication creates a new exact product-main candidate. It must earn a
fresh PASS across every ordinary hosted lane, including Windows CLANG64; no
result is inherited from `25415342b0f190241988ba0895855faebc1d7a00` or any predecessor. Linux FIRST remains
independently frozen at
`8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`. CLEAN remains **NOT RUN**
until an exact-candidate self-hosted receipt or an offline-verifier-accepted
owner-native receipt exists. Owner-native evidence is **MANUAL CLEAN PASS**,
never automated CI PASS.

## R9 hosted parser diagnostic after b15f64d rejection (2026-10-21)

Exact candidate `b15f64d35e5a12dcd83026e2abdc0b4dd1f22397`, primary Actions run
`39726139498`, is **REJECTED** because ordinary hosted
`r9-windows-powershell-parser` still fails with the same three PowerShell 5.1
syntax errors. The prior compatibility edit therefore does not qualify
product-main.

The parser gate now includes source extent line/column/text in its failure
message so the next correction is based on the exact hosted PowerShell 5.1
diagnostic rather than another syntax guess. This changes diagnostics only: it
does not weaken parsing, Windows CLANG64, CLEAN, FIRST, or any product/runtime
gate. FIRST remains frozen at
`8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`.

## R9 exact-SHA rejection and Windows PowerShell 5.1 compatibility repair (2026-10-21)

Exact product-main candidate `e68c3a18955eb4d00579ec8a467dd1e78c03bc7b`, primary Actions run
`39697358991`, is **REJECTED**. The ordinary hosted
`r9-windows-powershell-parser` job `119557889913` still reports a
PowerShell 5.1 parse failure, so no product-main qualification may be inherited
from that SHA. Structure/documentation/Linux GUI lanes passing on the same
candidate do not override the parser failure, and Windows CLANG64 coverage
remains mandatory.

The CLEAN producer keeps the same fail-closed receipt contract but uses syntax
with unambiguous Windows PowerShell 5.1 parsing: the WindowsPrincipal
construction uses explicit `-TypeName`/`-ArgumentList`, and
`RuntimeInformation` architecture enum properties are converted with a
`[string]` cast rather than invoking `.ToString()` on a static-property
expression. No CLEAN requirement, provenance label, non-admin check, PATH
check, socket check, or firewall/service/policy invariance check is weakened.

This repair creates a new exact product-main candidate and requires a fresh
complete ordinary-hosted PASS. FIRST remains separately frozen at
`8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`. CLEAN remains **NOT RUN**
until a real exact-candidate self-hosted or verifier-accepted owner-native
receipt exists; manual evidence must remain labeled **MANUAL CLEAN PASS**.

## R9 inherited R6 Windows PowerShell parser correction (2026-10-21)

R6 exact SHA `40650f9c24f6555b75e7f6a54f989d49118498a7`, primary run
`39696394298`, independently failed `r9-windows-powershell-parser` before
R9's later format-2 additions. Diff isolation against the last parser-green
script identifies R6's variable-argument pseudo-constructor
`New-Object Security.Principal.WindowsPrincipal($identity)` as the
parser-unsafe change. The supported Windows PowerShell positional-argument form
`New-Object Security.Principal.WindowsPrincipal $identity` preserves identical
runtime intent and restores parseability without weakening the non-admin gate.

## R9 PowerShell parser correction after exact-SHA rejection (2026-10-21)

Exact parent `6b99b2abdd599cc3e8d249b013927050ee8dd78f`, primary Actions run
`39696835169`, `r9-windows-powershell-parser` job `119556157940`:
**FAIL** before execution because Windows PowerShell 5.1 rejected the new
static-property `.ToString()` syntax. Product-main therefore remains
unqualified even if other parent lanes pass. The correction wraps
`RuntimeInformation` static properties before `.ToString()` and uses
ordinary statement assignments for manual/self-hosted provenance; no CLEAN
requirement or Windows coverage is weakened. This replacement publication
requires a fresh complete ordinary-hosted PASS.

## R9 reconciliation with R6 CLEAN receipt format 2 (2026-10-21)

Shared-main parent: `40650f9c24f6555b75e7f6a54f989d49118498a7`. R6's richer format-2 receipt is retained, but
R9 closes its acceptance-verifier gap rather than reverting it. Format 2 now
records the Windows OS/process architecture and explicit execution provenance,
plus the socket/PATH/environment observations required by the manual CLEAN
contract. The producer labels evidence **MANUAL CLEAN PASS** for owner-native
execution and **SELF-HOSTED CLEAN PASS** for the dedicated Actions runner.

`scripts/verify_clean_windows_receipt.py` now verifies format 2 offline. It
recomputes the receipt and ZIP SHA-256 sidecars, exact source and smoke-script
hashes, exact source SHA/archive identity, x86-64 OS identity, non-admin
interactive Explorer session, clean development environment, required packaged
files, launch/ordinary-close/relaunch observations, no TCP/UDP sockets before
Start, Windows-system-only child PATH, and equal before/after Windows
firewall/service/TermService/RDP-policy state hashes. Duplicate JSON keys,
missing/extra format-2 fields/checks, wrong provenance labels, script/ZIP
mutation and state drift fail closed.

Ordinary offline CTest
`packaging.windows-portable-gui-manual-clean-receipt-verifier-denials` is
restored. Authoring-only isolated verifier regression: **PASS 12/12**. No real
manual clean-Windows receipt was executed here, so CLEAN is still **NOT RUN**;
a future verifier-accepted manual record may satisfy CLEAN without being
misreported as automated CI.

FIRST remains separately frozen at
`8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`. This publication also creates a
new product-main exact SHA, which must earn a fresh all-ordinary-hosted PASS;
no parent qualification is inherited and Windows CLANG64 remains mandatory.

## R9 manual CLEAN route and split qualification ledgers (2026-10-21)

## Official manual CLEAN fallback when the dedicated runner is unavailable (2026-10-21)

R9 may accept a manual clean-machine record in place of the queued
`r9-clean-windows-gui` job only when it is produced by the exact source
verifier against the unchanged producer ZIP. On an ordinary interactive
non-admin Windows machine run exactly:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\clean_windows_portable_gui.ps1 -Archive .\rdp-server-portable-gui-<version>-windows-x86_64-<sha12>.zip -ExactGitSha <40-lowercase-source-sha> -Receipt .\clean-windows-receipt.json
```

The output pair is `clean-windows-receipt.json` and
`clean-windows-receipt.json.sha256`. R9 must independently verify the
sidecar hash, `status=PASS`, gate, format version 2, exact source SHA,
archive name/hash, exact-source verifier/smoke hashes, non-admin interactive
session, development-path/install-root absence, required-file/window-close/
relaunch observations, and equal before/after system-state hashes. The receipt
does not authorize native hosting or replace R2/R10. A record copied from a
different ZIP/source, missing its sidecar, or produced on a
provisioned/elevated machine is invalid.

No such manual receipt was executed while authoring this rule. CLEAN therefore
remains **NOT RUN / BLOCKED** until R9 verifies a real exact-candidate record.

Authoring shared-main base: `32627968bce27b5f3bab3b2fdc8b48433bf502e0`. This publication creates a new exact product-main SHA, so its ordinary hosted qualification starts from zero; no PASS is inherited from any parent.

| Ledger | Exact candidate/evidence | R9 rule |
|---|---|---|
| **FIRST Linux acceptance** | `8f2667b9d4a9dd09b05486e91c3277fc3cb4af72` | **FROZEN**. Product-main UX/password/native-host/portability commits must not move it. Physical owner-authorized visible desktop + mouse + keyboard + Stop remains **NOT RUN**. |
| **Product-main qualification** | this R9 publication SHA | Require every ordinary hosted lane green on this exact SHA, including Windows CLANG64. The `389de5a...` typed Qt lookup failure and `1fc5829c...` stale fake-product assertion are retained as real predecessor failures; do not weaken coverage to hide them. CLEAN is separate. |
| **CLEAN Windows** | exact producer ZIP + ZIP sidecar + receipt format 2 JSON + SHA-256 sidecar | The dedicated clean runner or a verifier-accepted owner-native receipt may satisfy CLEAN. Manual evidence is labeled **MANUAL CLEAN PASS**, never automated CI PASS. |

### Current M1 owner-authority correction

Older dated statements below that positive Linux owner authorization is structurally unavailable are superseded. Current `CurrentOwnerSharingAuthority::requestConsent()` can return `Granted` for fresh valid physical `seat0`, unlocked, local-owner evidence; `authorizes()` freshly revalidates scope, lifetime and native evidence. R2 additionally fences platform-native authorization to the exact grant/revocation epoch. Offline positive tests are source/state-machine evidence only; physical FIRST remains **NOT RUN**.

### Formal manual CLEAN receipt

Run the existing exact-SHA clean script against the unchanged exact producer ZIP and sidecar on a genuinely clean x86-64 Windows desktop user:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\clean_windows_portable_gui.ps1 -Archive <exact.zip> -ExactGitSha <40-hex-sha> -Receipt .\clean-receipt.json
```

Receipt format 2 records the exact source SHA, ZIP SHA-256, machine/Windows architecture, interactive non-admin/Explorer status, clean parent and isolated child PATH/environment checks, launch/close/relaunch, hidden offline tests, no process TCP/UDP sockets before Start, and firewall/service/TermService/RDP-policy+port invariance. The script writes `clean-receipt.json.sha256` over the exact receipt bytes.

Verify offline with the unchanged ZIP, ZIP sidecar, receipt and receipt sidecar:

```text
python scripts/verify_clean_windows_receipt.py --receipt clean-receipt.json --archive <exact.zip> --exact-git-sha <40-hex-sha>
```

The verifier recomputes both hashes, enforces strict two-space sidecars and the complete format-2 schema/check set, rejects duplicate JSON keys, and preserves provenance as **MANUAL CLEAN PASS** or **SELF-HOSTED CLEAN PASS**. Authoring-only isolated verifier regression: **PASS 8/8**. Real manual CLEAN execution: **NOT RUN**.

## R9 split qualification ledgers and R7 toggle co-change repair (2026-10-21)

PM policy separates Linux FIRST acceptance from moving product-main
qualification. These ledgers are independent and must not silently advance each
other.

| Ledger | Exact candidate | Hosted ordinary CI | Independent/manual gates | R9 disposition |
|---|---|---|---|---|
| FIRST Linux acceptance | `8f2667b9d4a9dd09b05486e91c3277fc3cb4af72` | PASS: ordinary hosted jobs, including documentation policy, are green | Owner-authorized R1 transport, R3 protocol, R4 frame/ACK, R5 X11 capture/input and R7 GUI lifecycle remain NOT RUN | **FROZEN** at this SHA; later password/UX work must not move it |
| Product-main qualification | moving `main`; parent `82feaad284dda584d203d877f6239abf44a246e3` is disqualified by missing Markdown co-change | Parent ordinary jobs are green except `documentation-policy`; this repair's replacement exact SHA is PENDING | CLEAN Windows remains separate; real Windows App/`mstsc.exe` password interoperability and later native-host gates remain independent | Require replacement exact-SHA ordinary hosted PASS before qualification |

The R7 toggle import is present in the desktop GUI build through
`CMakeLists.txt`, but the parent implementation commit omitted Markdown. This
section plus the canonical ROADMAP entry is the permitted documentation-only
repair for that actual policy failure; it does not change acceptance goals.

Product-main R9 guard inventory, to be enforced without weakening existing
tests: one-page dashboard replaces the wizard; the shared toggle source is in
every applicable GUI build; default user-facing dashboard text contains no
R1/R2/R10 road labels; password controls are absent until the capability is
enabled by real interoperability evidence; tray/menu-bar Start/Stop/exit
lifecycle is covered; automatic address presentation is covered; and every
current source/CMake/test/workflow change has a Markdown co-change. CLEAN
Windows may advance only from a clean non-admin exact-artifact execution or a
matching signed/hashed manual acceptance record, never from hosted Windows CI.

Do not create documentation-only churn while a qualifying run is active unless
repairing a concrete policy failure.

## R9 post-R10 resize integration guard repair (2026-10-19)

Exact main `f894dd23fdfd3598335fd85f1269fc7ae36ae17c` lands R10's authenticated native RandR resize
scheduler, clearing the R3 -> R10 **RESIZE** dependency in the project graph.
Its first primary Actions run `39290204071` passed the hosted Windows
PowerShell parser, R9 sanitizer inventory, R6 Windows CLANG64, Windows/macOS
protocol, R5 Linux GUI ZIP, R7 macOS GUI/lifecycle/session lanes, R2 production
security variants, workflow structure and documentation policy. Ubuntu protocol
failed exactly one source-contract CTest,
`runtime.linux-r5-persistent-x11-input-frame-borrow-order`.

That failure is an integration guard mismatch, not a native resize/runtime
failure. R10 correctly added an earlier `frameWritePending = true` when a
surface reconfiguration starts so the existing Graphics writer can drain
DELETE -> CREATE -> MAP. The R5 source guard previously searched for the first
such assignment and therefore mistook the remap writer for frame publication.
This commit scopes the assertion to the source tail beginning at
`consumeR4Frame(...)`, preserving the intended requirement that successful
synchronous R4 frame borrowing precede the frame-publication pending state.
No production code, authority decision, protocol ownership, or release policy
is changed.

**Historical note:** that 2026-10-19 state is superseded by current M1 positive grants from fresh valid physical seat0/unlocked same-UID evidence. Physical FIRST remains NOT RUN.
**CLEAN remains blocked** operationally because no interactive non-admin
`r9-clean-windows-gui` receipt exists; the exact Windows candidate must not
be promoted to a public PORTABLE-GUI until that consumer runs successfully.
The publication SHA for this guard repair requires its own exact-SHA CI result;
do not inherit overall PASS from `f894dd23fdfd`.

## R9 post-R3-merge main stabilization and dependency refresh (2026-10-19)

Exact main `e24539c78f6c42be9bb1357247c1685d8161b45b` merged R3 PR #24. Its R3 source had exact-head hosted
validation before merge, and R4's same-generation AVC420 remap reset, R5's
RandR generation repairs, R7's GUI build/TLS presentation repairs, and R10's
ACK-credit/polling plus GUI-default split are already on main. The merge does
not change R9's clean-Windows verifier or release-gate source blobs.

The first main push run after the merge, Actions `39288900663`, immediately
passed the independent hosted Windows PowerShell parser and workflow structure
guards. It then failed `documentation-policy` because the merged R3 history
contained nine source/test commits without a repository Markdown co-change.
This ledger-only commit is the narrow integration repair; it changes no R3,
R4, R5, R6, R7, R9, or R10 runtime behavior. The new publication SHA must be
judged by its own Actions run and must not inherit an overall PASS from the PR
head or an earlier main SHA.

Dependency refresh: R3 is no longer the resize blocker. Production native
resize remains blocked on R10 scheduler wiring: current
`LinuxRuntimeConnection` exposes frame preflight and handles R3
DELETE/CREATE/MAP write kinds, while the R2 broker exposes
`beginR3PersonalDesktopGraphicsSurfaceReconfiguration(...)`, but the runtime
loop still has no production call that observes fresh native geometry and
starts that reconfiguration. At that historical SHA the positive path was structurally blocked. Current M1 can grant/revalidate valid physical owner evidence; physical FIRST remains NOT RUN.

R9's remaining release blocker is still operational, not source-level: no
qualifying interactive non-admin runner/receipt exists for
`r9-clean-windows-gui`. The last pre-R3 exact-main run at
`9a1916a93c327da164463890f36557ae26b1166c` had all ordinary hosted jobs
green and the clean-Windows job queued. Do not publish the public Windows
PORTABLE-GUI or claim clean-machine PASS until the exact candidate ZIP and
sidecar execute successfully on that clean environment and produce the matching
receipt.

## R6 Windows GUI producer re-enabled after R9 headless overreach (2026-10-19)

Current-main parent `1d5ff7597e5382b178fb0afa668db93849de778c` inherited R9 commit
`9e4222cfe909ad3aabee6d0bb0a99142f0354877`, which changed both
`r6-windows-clang23` Debug and Release producer configures to
`RDP_SERVER_BUILD_DESKTOP_GUI=OFF` while the very next commands required the
cache value to be `ON`. Actions `39274959607`, R6 job `118136799203`,
therefore failed in **Configure Debug with CLANG64**: CMake was invoked with
GUI OFF and the exact `RDP_SERVER_BUILD_DESKTOP_GUI:BOOL=ON` assertion exited
1. Those two producer configures are Qt-capable and must remain ON; only the R6
sanitizer reconfigure is intentionally GUI OFF. The workflow and both release
gate/structure regressions now enforce exactly that ownership.

The last fully produced R6 Windows GUI candidate remains exact source
`1b28ad3e51b761bb2f79a7066b579d6b12610ba2`, Actions
`39273084795`, R6 job `118130308229` **PASS**. Debug and Release CLANG64
full CTest each passed **691/691**; R6 native preflight passed **59/59** in each
configuration; R10 private-fixture security preflight passed **3/3** and
**5/5** groups in each configuration; unsupported-password GUI CTest passed
**1/1**; native packaging/PE closure passed **41 images / 571 imports**;
extracted GUI first-screen/no-socket/rerun/native system-state smoke **PASS**;
R6 sanitizer selection passed **59/59**. The ordinary Windows MSVC lane at the
same SHA passed Debug and Release **673/673**, including
`packaging.windows-portable-gui-clean-release-structure-denials` on native
Windows.

Internal artifact `12197052099`,
`r9-windows-unverified-1b28ad3e51b761bb2f79a7066b579d6b12610ba2`,
has Actions-container SHA-256
`f0f1b706ee388a078be3ba8b4c3b32e87cce6acc359e6513e337c0292e03fe59`.
Its exact inner user ZIP is
`rdp-server-portable-gui-0.1.0-windows-x86_64-1b28ad3e51b7.zip`, SHA-256
`d1e0ea0981fdc0b51674fbb66fa5eee3ffa39f18912a751c243aa28cf89fe532`;
the sidecar matches. Independent extraction verifies 40 bundled DLLs, 41
x86-64 PE images, 531 GNU-objdump imports and zero unbundled non-system imports;
all manifest/internal SHA-256 records match. The 40 DLL names and hashes are
identical to the prior `2fcfebee...` candidate. No owner-provided failed human
ZIP is available for byte comparison, so that specific dialog/DLL remains
unverified.

The clean non-admin Windows consumer for the `1b28...` run is still **QUEUED
/ NOT RUN** on `r9-clean-windows-gui`; only the internal unverified artifact
exists and no public `rdp-server-portable-gui-windows-x86_64` artifact has
been published. Windows portable release therefore remains **BLOCKED**. R6
read-only firewall/TermService/RDP-policy/requested-port checks are unchanged.
Positive Windows RDP serving remains independently **BLOCKED** on R2
SSPI/CredSSP authenticated revocable SID/WTS authority and a concrete R10
Windows WTS/session owner.

## R9 `9e4222cf` CI receipt — Windows compile failure (2026-10-19)

Exact SHA `9e4222cfe909ad3aabee6d0bb0a99142f0354877`, Actions
`39274959607`: hosted PowerShell parser **PASS**; primary workflow structure
**PASS**; Linux GUI build/package **PASS** with artifact `rdp-server-gui-linux`
ID `12197007323`; `protocol (windows-latest)` **FAIL** at MSVC compilation
because `std::numeric_limits<std::uint64_t>::max()` collided with the Windows
`max` macro. Therefore this SHA is not a release PASS.

The downloaded Linux artifact contains inner ZIP
`rdp-server-gui-0.1.0-linux-X64-9e4222cfe909.zip`, SHA-256
`0f9bedb20e1c52a1023e9f01bae740b2d2ce33494f5161524b6cb9d2c9e018c7`,
with `bin/rdp-server-desktop`, `run-gui.sh`, `RDP Server.desktop`, and
`plugins/platforms/libqxcb.so`; the CLI `rdp-server` is absent. Clean Windows
remains **BLOCKED / NOT RUN** and no public Windows PORTABLE-GUI receipt is
claimed.

## R9 exact checksum/parser gate and clean-runner receipt contract (2026-10-19)

Authoring parent: `1bc7dc8e779b8b003b6cde07e0efeb6a01560a1e`. On exact baseline
`2fcfebee9e94b064ebf54617cd224982060471a0` / Actions `39244189634`, macOS
arm64 PORTABLE-GUI `rdp-server-portable-gui-macos-arm64` (`12183271544`) was
downloadable. Windows had only internal exact-SHA candidate
`r9-windows-unverified-2fcfebee9e94b064ebf54617cd224982060471a0`
(`12182782501`) because clean Windows was queued; no public Windows GUI was
released. Linux GUI was absent because its build failed. `protocol-package-*`
are SDKs and `server-test-package-*` are startup-disabled SERVER-TEST bundles.

GUI entrypoints: Windows `RDP-server-GUI.exe` + `plugins/platforms/qwindows.dll`;
macOS `rdp-server-desktop.app/Contents/MacOS/rdp-server-desktop` + Cocoa plugin;
Linux `bin/rdp-server-desktop` via `run-gui.sh` / `RDP Server.desktop` +
`plugins/platforms/libqxcb.so`.

### Provisioning `r9-clean-windows-gui`
Use a disposable Windows x86_64 snapshot with a standard non-Administrators
user in a real Explorer desktop. Launch the Actions runner interactively in
that same session, never as a service/Session 0, with labels
`self-hosted,Windows,X64,r9-clean-windows-gui`. Do not provision MSYS2, Qt,
LLVM/Clang, CMake, OpenSSL, vcpkg, SDK development paths, or repair tooling.
Do not mutate firewall, TermService, RDP policy, service modes, or ports.

Consume only `r9-windows-unverified-<exact SHA>` from the same producer run;
keep the inner ZIP and `.zip.sha256` unchanged. Preserve non-admin Explorer,
OS-only child PATH, Unicode/space extraction, first window, hidden tests,
close/relaunch, process TCP/UDP checks, and firewall/service/RDP-state equality.

### Manual receipt fallback
Transfer unchanged exact producer ZIP/sidecar and exact-SHA `scripts/`, require
the hosted parser job green, then run:
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\clean_windows_portable_gui.ps1 -Archive <exact-zip> -ExactGitSha <40-hex-sha> -Receipt <receipt.json>`
Accept only exit zero with matching exact SHA/archive/outer SHA-256 and
`non_admin_interactive: true`. No operational receipt exists at authoring:
**clean Windows remains BLOCKED / NOT RUN**.

## R6 clean-gate regression follow-up (2026-10-19)

The PowerShell consumer repair in `67ea710697dfbcdc9dafb1badb047c50b61ece07`
was correct, but that commit's generated Python regression source was malformed.
Follow-up `e9c4abb43efb59ff24c9eceda594da3c6503452a` restores
`tests/test_r9_clean_windows_gate.py` from the pre-change source and reapplies
only narrow fail-closed checks: the checksum inventory owner, explicit
`[regex]::Match`, `Groups[2].Value` access and terminal clean-PASS marker
must each occur exactly once; duplicate tails are denied. On Windows, the same
ordinary full-CTest file additionally parses
`scripts/clean_windows_portable_gui.ps1` through
`System.Management.Automation.Language.Parser`.

Source inspection of the follow-up is **PASS**. Exact publication-SHA CTest/CI
is **PENDING** at authoring; clean interactive non-admin exact-ZIP execution is
still **NOT RUN / BLOCKED** pending `r9-clean-windows-gui`. The package,
OS-only child PATH, firewall/TermService/RDP-policy/requested-port read-only
contracts and the R2/R10 native-host blockers are unchanged.

## R6/R9 clean Windows verifier repair — release still blocked (2026-10-19)

Authoring parent `660068b5719e1d997b782b90a5fc928cc9e2133f`. The clean-Windows consumer on current main still
contained the malformed `e2e48f0f` splice: its SHA256SUMS regex was truncated and
the post-checksum body was duplicated, so the queued self-hosted consumer could
not provide valid PowerShell execution evidence. Restore the last known-good
consumer body and keep the intended explicit `[regex]::Match` capture object.
The existing full-CTest gate
`packaging.windows-portable-gui-clean-release-structure-denials` now rejects
a truncated/duplicated checksum parser, and on Windows additionally parses the
actual consumer with `System.Management.Automation.Language.Parser`.

Independent exact-artifact inspection remains separate from the clean-machine
gate. Main source `2fcfebee9e94b064ebf54617cd224982060471a0`, Actions
`39244189634`, R6 producer job `118032566420` **PASS**, emitted internal
artifact `12182782501`. Its GitHub Actions container SHA-256 is
`caea4cb15be32f2fac5f3bea7eed0913cd397ceb8841135c91df526465a4ed8e`;
the contained exact ZIP SHA-256 is
`61484dc968ba3d478dd66b74c1c22f482e210d1ff9e4a7a3a0e81377303240bb`.
Offline inspection finds 40 bundled DLLs, 41 PE images, all x86_64, 531 parsed
imports with GNU objdump and zero unbundled non-system imports under the R9
system-DLL policy. The 40 DLL names and hashes match the previously inspected
PR #25, PR #26 and `aee09e50` candidates. The owner-provided failed human ZIP
is still unavailable, so byte parity and its exact loader dialog/DLL remain
**UNVERIFIED**. The earlier proven packaging defect was `windeployqt` omitting
`libc++.dll` plus ICU, PCRE2, zlib/zstd, freetype/harfbuzz, PNG/JPEG,
Brotli and GLib dependencies; `ab63d1bb` already stages that recursive
non-system closure app-local.

No clean interactive non-admin Windows receipt is claimed by this source
repair. The public Windows portable release remains **BLOCKED** until the
self-hosted `r9-clean-windows-gui` job executes the exact newly produced ZIP
with Windows-system-only child PATH and publishes its matching receipt. R6's
read-only firewall/TermService/RDP-policy/requested-port observations are
unchanged. Positive Windows RDP serving remains independently **BLOCKED** on
R2 SSPI/CredSSP authenticated revocable SID/WTS authority and a concrete R10
Windows WTS/session owner.

## R9 clean Windows release-blocking gate and concurrent integration (2026-10-19)

Reconciled R9 PR #26 `b45582b466de80a5423e4e38feac134266942355` (primary Actions 39232727915 PASS;
independent structure 39232727808 PASS) against main `59357e2fe6eaa4937b337b5d1e73ed82634daab9`,
preserving concurrent R4 ACK duplication repair, R5 RandR work, R6
Windows offline contracts, and R10 fail-closed HostControl changes.
The R6/R9 clean-Windows workflow introduced on main contained a truncated
PowerShell checksum expression and duplicated job graph and uploaded the
public Windows ZIP before clean verification; this integration replaces
the broken workflow with the known-valid PR #26 full workflow plus a
strict release-blocking consumer job.

CLANG64 now publishes only an internal `r9-windows-unverified-<SHA>` ZIP
after recursive PE closure and its existing extracted qwindows smoke.
A separate interactive non-administrator, genuinely unprovisioned Windows
VM with runner label `r9-clean-windows-gui` downloads the exact unchanged
ZIP. The consumer rejects missing hashes/license notices/manifest,
malformed archive or platform identity, non-app-local Qt/DLL loading,
missing first window, close/relaunch/hidden-test failure, TCP/UDP socket
activity, Unicode/spaces regressions, firewall/service/TermService/RDP
policy modifications, elevated/system session and development PATHs.
It produces an exact-source acceptance receipt before releasing the
public Windows x86_64 PORTABLE-GUI artifact; no missing-DLL dialog can
be classified as PASS.

**Release BLOCKED:** clean interactive non-admin Windows VM and its
exact-SHA PASS receipt are NOT YET VERIFIED. If no runner is registered
the public ZIP intentionally remains unpublished; hosted MSYS2 and
provisioned Windows-latest cannot replace it. Linux x86_64 and macOS
arm64 GUI artifacts remain separate from SDK and disabled SERVER-TEST.
PR #23 GUI default ON / Qt-free headless remain unmerged. Real R2 owner
consent, R10 LAN GUI Start, R3 live resize, R8 clipboard and real
Linux seat0 to Windows App/mstsc acceptance remain independent blockers.
Linux, CLANG64 and macOS27 full owner-native exact-SHA Debug CTest
remain NOT RUN for the integration SHA.

# R9 portable GUI distribution and acceptance ledger

Baseline: `7f7f6b0dc5d5c47117b0fdf4cf223d54e547af91` (primary Actions 39157893314, independent structure 39157893350). These baseline runs passed; the baseline artifact list contains `rdp-server-gui-linux`, but no separately downloadable Windows or macOS PORTABLE-GUI archives.

## R9 CI publication correction

The Windows CLANG64 packaging lane already builds and verifies a PE/DLL-closure checked x86_64 ZIP, then performs an extracted, path-with-spaces, offline GUI smoke. The macOS arm64 lane already builds, checks Mach-O closure and extracted ad-hoc signature, and performs an extracted Cocoa launch. Upload the ZIP and its SHA256 file only after the corresponding native smoke passes. Linux keeps the separately named `rdp-server-gui-linux` artifact and Linux/XCB extract/launcher preflight. These are portable GUI previews, not protocol SDK packages or startup-disabled SERVER-TEST archives.

Each candidate artifact must retain its full source SHA manifest, outer SHA256, licenses/notices, architecture, and dependency inventory. Do not claim Windows/macOS artifacts are available until a **new exact-SHA CI run** succeeds and lists them. Do not substitute hosted package checks for owner-native Debug/Release evidence. macOS ad-hoc preview signing is **not** Developer ID distribution or notarization.

The R3 DVC sanitizer selector must remain exactly **20** registered cases including `transport.dvc-graphics-frame-credit-preflight`; R8 clipboard component sanitizer selector remains exactly **87** and separately asserts native bridge/linkage source guards. R4 surface geometry, R2 IPv4-mapped IPv6 admission quota, R7 Qt client stage, and R8 stable scalar clipboard receipt require exact-HEAD CTest inventory verification; a general green matrix alone does not prove focused selection. Do not lower a pinned count to disguise changes.

## Physical/owner acceptance ledger — NOT RUN

| Acceptance gate | Status | Required evidence |
|---|---|---|
| GUI-only existing OS-account setup, authorization and seat0 owner | NOT RUN | Real logged-in owner/session receipt, no synthetic permission |
| LAN Start / Stop, no unauthorized side effects | NOT RUN | GUI action and socket/firewall before/after evidence |
| Microsoft-client CredSSP and Share | NOT RUN | Real mstsc/Windows App handshake and protected admission |
| First video frame and FRAME_ACK | NOT RUN | Correlated server/client frame ID and accepted-byte/ACK receipts |
| Keyboard/mouse input | NOT RUN | Genuine owner-authorized input and revocation |
| Resize / surface recovery | NOT RUN | Client-driven resize with surface retirement and new valid frame |
| Disconnect / Stop / exit / rerun | NOT RUN | Native lifecycle and zero post-retirement callback evidence |
| Offline-LAN operation | NOT RUN | Disconnected-from-Internet real LAN client run |
| M1 Linux/X11 owner-native Debug | OPEN | Same candidate SHA, owner hardware/toolchain, full CTest |
| M1 Windows MSYS2 CLANG64/Clang23 owner-native Debug | OPEN | Same candidate SHA, owner hardware/toolchain, full CTest |
| M1 macOS 27 owner-native Debug | OPEN | Same candidate SHA, owner hardware/toolchain, full CTest |

No candidate freeze before R10 nominates a single SHA. Hosted successes cannot advance any NOT RUN row.

## R9 focused exact-HEAD inventory — added source gates, CI NOT YET VERIFIED

R9 now explicitly builds `test_authentication_attempt_limiter` in the
Clang sanitizer job and independently pins the following registered CTests:
`security.ipv4-mapped-ipv6-peer-quota-identity`,
`graphics.surface-resize-revocation`,
`graphics.x264-native-bgra-resize-recovery`, and
`runtime.r8-r3-stable-scalar-write-receipt`. Each must match exactly one
CTest and execute with ASan/UBSan. R7's real Qt/macOS arm64 packaging job
separately pins and executes exactly one
`gui.offscreen-r10-client-stage-and-retirement-status-denials`.
The preexisting 20-case R3 Graphics DVC, 87-case R8 clipboard component,
and independent native linkage guards remain unchanged.

No hosted run, native owner receipt, or real Microsoft-client acceptance is
claimed for this addition until corresponding exact-SHA evidence exists.
`src/gui/main.cpp` still constructs `UnavailableRuntimeHostControl`;
R10 concrete GUI LAN Start/Stop and R2-backed owner admission have not landed.
The R10 candidate freeze nomination and same-SHA M1 native Debug receipts
remain OPEN.

## R9 verified hosted GUI distribution and current merged-owner inventory (2026-10-18)

Exact shared R9 SHA `aee09e5035721ff14f635e670a982392e87c53b7`, primary Actions
`39201911316`, has successful hosted Clang ASan/UBSan focused inventory
(R2 IPv4-mapped IPv6, R4 surface/resize and R8 scalar receipt), R7 Qt
client-stage, R6 Windows CLANG64 and Windows/MSVC, R5 Linux GUI, R7 macOS
arm64 portable GUI, all protocol OS jobs, and SERVER-TEST acceptance.
R3 Graphics DVC **20/20**, R8 clipboard **87/87**, and native linkage
guards remain independent; counts are not reduced.

The three separately downloadable same-SHA Actions artifacts and their
**GitHub Actions container** SHA-256 digests (not ZIP-internal hashes) are:

- Windows x86_64 `rdp-server-portable-gui-windows-x86_64` artifact
  `12163794986`: `08ad07de2b8075b7817754e702f5cd5d5c89c2a2c68c9cbcb84ba8c08228353a`
- Linux x86_64 `rdp-server-gui-linux` artifact
  `12163719180`: `8b2b5042385eebe87b4e1cf33d3b22743f030fb6305f4ee73fe7bc3b093968b1`
- macOS arm64 `rdp-server-portable-gui-macos-arm64` artifact
  `12164610862`: `ad07eab4938a1e0313b0fb809213edb925f9018429beb58979691cfb39710f9a`

Native hosted archive/Qt/PE/ELF/Mach-O closure and extracted offline smoke
checks passed in that run. The packaged ZIP and its `.zip.sha256` file
still require independent consumer validation against their manifest and
license/notices; Actions-container digests must not be represented as
the inner ZIP hash. macOS ad-hoc `codesign --verify --deep --strict`
is **not** Developer ID distribution or notarization.

Merged R7 `gui.offscreen-r10-lifecycle-and-terminal-close-denials` is also pinned exact-one in the real macOS Qt lane. Merged R2 `security.linux-seat0-session-identity-denials` and
`runtime.host-control-authentication-outcome-denials` now receive exact-one
ASan/UBSan CI selections with both real fixtures compiled; merged R7
`gui.offscreen-close-requires-explicit-owner-stop` receives exact-one
real macOS Qt offscreen CI selection; merged R8
`runtime.r8-r3-retired-route-positive-receipt-isolation` is added to the
existing focused R8 ASan/UBSan selection, remaining outside R8's fixed 87
clipboard component tests. R2's fixed 40-case direct-runtime, R3's 20-case
DVC, R8's 87-case clipboard and linkage guards remain unchanged.
The first PR-head CI attempt reached PASS for structure, Linux sanitizer, macOS portable GUI, Linux GUI, macOS protocol and R7 lifecycle jobs before this rebase; Windows jobs were still running. This rebase adds the newly merged R7 lifecycle/terminal-close exact-one CTest, so the new head is **NOT YET HOSTED VERIFIED**.

R10's `UnavailableRuntimeHostControl` is still used in production GUI
`src/gui/main.cpp`; the separate R10 ACK-credit/HostControl PR #23 and R3
geometry remap PR #24 remain draft/unmerged. The latter intends to grow
the R3 DVC selection from **20 to 21** only with its new registered test.
Physical Linux seat0 owner consent/lock proof, genuine LAN Start/Stop,
Microsoft-client CredSSP/Share/first frame/FRAME_ACK/input/resize/reconnect,
owner-native M1 Debug matrix and R10-nominated candidate freeze remain
**BLOCKED / NOT RUN**. No hosted offline preflight substitutes for them.

