# R6 Windows GUI and native admission boundary

The optional Windows Qt6 Widgets target `rdp-server-windows-gui` creates
`RDP-server.exe` as a windowed, unprivileged executable. It is **a
fail-closed GUI shell**, not yet an operational LAN host. A normal double
click opens LAN mode, address, sessions and disabled account/Start/Stop
controls. No listener, service, firewall, task, autostart, download or
native input is started or altered. The offline CTest
`windows.gui-offline-no-side-effects` exercises its argument-mode startup
without entering Qt or making OS changes. R7 replaces this temporary UI
surface with the common Qt GUI; the target name is the integration seam.
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
