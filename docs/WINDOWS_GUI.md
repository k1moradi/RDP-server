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

## R6/R9 clean consumer verifier integrity correction (2026-10-19)

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

# R6 Windows GUI and native admission boundary

The optional Windows Qt6 Widgets target `rdp-server-windows-gui` now
compiles R7's shared `DesktopWindow` into a windowed, unprivileged
`RDP-server-GUI.exe`. It is a **fail-closed GUI shell**, not a LAN host.
The distinct name avoids colliding with the existing startup-disabled
`rdp-server.exe` CLI on case-insensitive Windows volumes. On double click,
the common GUI shows onboarding, address/session status, and disabled
credentials/Start/Stop until real host authority exists. No listener,
service, firewall, task, autostart, download or native input is triggered.
`windows.gui-offline-no-side-effects` and
`windows.gui-start-denied-without-r2-r10` instantiate the actual R7
window via Qt's offscreen plugin to check blocked controls and the production
deny-only HostControl. They do not substitute for portable ZIP security tests.
R9 owns staging a verified portable ZIP with all Qt platform plugins, Qt/CRT,
OpenSSL and other non-system DLLs, a per-file integrity manifest and a
double-clickable exe. No portable ZIP closure is claimed delivered here.

R2 must privately mint a live, revocable, CredSSP/SSPI-authenticated user SID
lease, independently matched to the **active physical interactive WTS
console** identity including WTS session ID, full LUID and logon time.
A process token observation, accepted TLS connection, and Win32 console
evidence do not grant this lease. R10 must publish one authoritative host
status and serialized Start/Stop control API, including exact lease/session
generation. The GUI must remain disabled until that API positively reports
native host readiness; it cannot compose its own readiness from weaker facts.

The R10 interactive session owner checks lease identity before each DXGI
frame borrow and SendInput action. On revocation, logoff, WTS reuse, session
switch, lock, display loss, reconnect or shutdown, it retires the generation
synchronously: **no SendInput after revocation**. Retire pending D3D11 staging
maps and DXGI frames in Acquire/Map/Consume/Unmap/ReleaseFrame order, release
COM objects on their owning context/thread after outstanding frames finish,
then create a new device generation. Never promote old captured frames or
cursor/input events to the replacement generation.

Store future mutable settings under the private per-user Windows application
data location, never beside an extracted executable; R2 must use an OS-backed
credential provider/store. All package paths (including Unicode and spaces)
must remain writable only where appropriate; extracted executable and DLLs
are read-only payload, not installation targets. On explicit Start, any
firewall or permission guidance must be opt-in and actionable, not a silent
rule mutation or privilege escalation. Never occupy an assumed 3389 or
restart/take over TermService.

Offline package gates for R9/R6: Unicode-and-space extraction/launch;
hash-verification of every staged file and Qt plugin dependency; non-admin
execution without extra PATH; no network/firewall/service/task side effects;
unavailable-admission Start denial; malformed/traversal/reparse path refusal;
and removal of extracted tree plus private settings without touching Windows
RDP. Genuine native-serving acceptance remains BLOCKED until R2/R10 provide
real interfaces. Windows App and mstsc.exe should first exercise the
Linux-host server separately from this Windows-host milestone.


## R10/R9 contracts now consumed by Windows packaging

R7 now supplies the shared Qt adapter to R10's typed RuntimeHostControl, and the Windows launcher instantiates that production contract through the deny-only runtime facade. R6 therefore does not add a second control owner. The remaining positive Start path still depends on a concrete R10 Windows backend and genuine R2 Windows admission.

R6 now provides packaging/windows/gui_bundle.py. It first runs local windeployqt, then uses CMake file(GET_RUNTIME_DEPENDENCIES) over the staged GUI and plugin DLLs to resolve the recursive non-system PE closure from the staged tree, Qt/toolchain directories and PATH. Windows API-set names are pre-excluded and resolved Windows system paths are post-excluded; missing non-system dependencies fail closed. Resolved regular DLLs that windeployqt omitted are copied into the GUI root before hashing. The builder requires Qt6Core/Gui/Widgets and plugins/platforms/qwindows.dll, rejects reparse links, unsafe or case-colliding paths, installer/script helpers and unexpected extra executables, and emits R9's exact PORTABLE-GUI manifest/checksum contract plus an adjacent outer SHA-256 receipt. The portable CTests use Unicode and space-containing paths, validate the archive with R9's production verifier, prove injected toolchain DLL staging, and exercise extraction/removal without executing or installing anything. R9 remains the independent native PE-import authority and must classify genuine Windows system DLLs rather than require their redistribution; extracted-GUI offline launch and firewall-state evidence remain native CI responsibilities.

## Packaged command-mode Qt platform contract

The Windows portable ZIP guarantees the native Qt `qwindows` platform
plugin. The hidden `--offline-self-test` and
`--offline-start-denial-test` command modes therefore force
`QT_QPA_PLATFORM=windows` and return before `QApplication::exec()`; they
construct the production shared window but never call `show()`. They must
not depend on Qt's optional `qoffscreen` developer/test plugin. The ordinary
double-click path remains unchanged and still shows the real top-level window.
The dedicated
`windows.gui-offline-packaged-qwindows-selection` CTest starts with an
intentionally invalid inherited QPA selection and requires the launcher to
override it. This changes no listener, credential, firewall, service,
capture/input or R2/R10 authority behavior.


## Hosted Windows portable-package evidence

The packaging path is now proven on hosted MSYS2 CLANG64. Exact descendant
`aaff05a91d4b903dbf7d7469247d6ad9225a76b4`, primary run
`39131193194`, Windows job `117686690036`, records Debug and Release full
CTest **641/641**, the R6 native selector **59/59** in each configuration,
`PORTABLE-GUI archive structure PASS`, recursive PE closure over **41 PE
images / 571 imports**, extracted deny-only modes, two ordinary first-screen
launches, no process-owned TCP/UDP sockets, ordinary close/rerun, unchanged
Windows firewall profile state, and the sanitizer R6 native selector **59/59**.
This is package/runtime assurance only; it does not grant Start authority or
prove a real Windows RDP host session.

The remaining Windows host gate is outside R6 packaging. R2 must provide a
genuine SSPI/CredSSP-authenticated SID and bind it privately to the exact active
physical-console WTS identity including full LUID and logon time with revocable
generations. R10 must then own WTS registration/events, native-session lifetime,
Start/Stop status and revocation, and must reauthorize immediately before each
DXGI borrow and SendInput call. The existing
`windows_native_session_evidence.*` reader is observational only and cannot
mint that authority.

## R6/R9 clean-ZIP release gate (2026-10-19)

Require unprovisioned Windows-runner launch of the EXACT CI ZIP with
Windows-system-only child PATH, actual GUI window, normal close and repeated
Unicode-and-spaces extraction. Source gate introduced; PASS is not yet
claimed. Human missing-DLL failure remains release blocking until the human
ZIP is compared and exact missing DLLs are identified. R2/R10 hosting gates
remain unchanged.

The R6/R9 workflow parses the adjacent SHA-256 receipt with an explicit
[regex] match object before comparing the filename and digest. This avoids
PowerShell automatic match-variable lifetime assumptions and keeps malformed
receipts fail-closed. The exact clean-runner acceptance check remains pending
on this publication SHA; prior hosted smoke does not qualify as clean PASS.
