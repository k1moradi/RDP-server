# Windows SERVER-TEST bundle

## R6 aggregate Windows native-owner boundary (2026-10-21)

The native Windows graph now exposes one future R10 composition type,
`WindowsNativeDesktopOwner`. It consumes R2's real const
`WindowsNativeDesktopAuthorization` plus the expected authorization
generation at open/service/input boundaries. Positive native activation remains
false until R10 composes the live owner; candidate WTS/SID/LUID/logon evidence,
geometry and DXGI state cannot authorize construction. The Win32 SendInput
bridge is private to this aggregate owner.

`windows.native-owner-r2-grant-and-lifetime-denials` is an offline
compile/lifetime sentinel only. It uses an unbound real R2 authorization
object, creates no fake positive grant and performs no live WTS, DXGI, cursor
or SendInput operation. Positive Windows hosting therefore remains gated by
real R2 client authentication plus R10 composition and does not change the
bundle's existing Start-denial behavior.

The Windows artifact is a **startup-disabled test bundle**, not an accepted
native RDP server. It may be installed and verified before Windows admission is
implemented, but its Start action deliberately fails closed.

## Artifact contract

R9 builds the real Release `rdp-server.exe` and records the exact Git SHA,
version, compiler, architecture, ABI, runtime dependency closure and per-file
SHA-256 values in `metadata/SERVER-TEST-MANIFEST.json`. The archive also
contains the safe loopback configuration template, LICENSE, NOTICE,
third-party attribution, `metadata/SHA256SUMS.txt`, the R6 lifecycle script,
and every resolved non-system Windows runtime DLL beside the executable.

The verified baseline at `9a2d09968e741d13bc1c5e76753ecaf1be7557ef` is
MSVC 19.51.36260.0, x86_64, PE32+ Windows ABI with
`libcrypto-3-x64.dll` as the only resolved non-system runtime DLL.
Windows/System32 and API-set components are OS-supplied. Future bundles use
their own manifest and resolver output as the authority.

CI emits the ZIP, adjacent `.zip.sha256`, status JSON, and an adjacent copy
of the PowerShell lifecycle plus its own SHA-256. The identical lifecycle
script is also inside the archive and covered by the internal manifest.

## Per-user lifecycle

Run from an ordinary interactive Windows user account; administrator elevation
is neither required nor requested.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\rdp-server-test-...-lifecycle.ps1 -Action Install -ArchivePath .\rdp-server-test-...zip
powershell -NoProfile -ExecutionPolicy Bypass -File .\rdp-server-test-...-lifecycle.ps1 -Action Verify
powershell -NoProfile -ExecutionPolicy Bypass -File .\rdp-server-test-...-lifecycle.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass -File .\rdp-server-test-...-lifecycle.ps1 -Action Start
powershell -NoProfile -ExecutionPolicy Bypass -File .\rdp-server-test-...-lifecycle.ps1 -Action Stop
powershell -NoProfile -ExecutionPolicy Bypass -File .\rdp-server-test-...-lifecycle.ps1 -Action Uninstall
```

The default root is
`%LOCALAPPDATA%\RDP-server\server-test`. Install verifies the adjacent
archive checksum, the archive manifest and internal checksums before extracting
through a private staging directory. Reparse points, parent traversal,
drive-qualified archive members, duplicate entries, missing runtime DLLs and
modified installed trees are rejected. Repeated install/uninstall is
idempotent only when the verified installed content is unchanged.

No lifecycle action downloads content, writes a firewall rule, registers a
Windows service, creates a scheduled task, configures autostart or silently
moves execution into LocalSystem/Session 0.

## Start status

`Start` currently returns exit code **3** after verifying the install and
reports **BLOCKED**. It does not invoke `rdp-server.exe` or open a listener.
Native Windows serving remains gated on all of the following:

- R2 must provide a private revocable SSPI/CredSSP-authenticated SID lease bound
  to the approved interactive physical-console WTS session and its logon
  identity/generation.
- R10 must serialize ownership of that admitted interactive Windows session;
  no interactive Windows Service or Session 0 workaround is permitted.
- R3 fragmented Graphics DATA publication is now present in source at
  `27f68c322fc13c7712c0393f7ca479ee4599a0c7`, with hosted validation
  pending. R10 must consume that route only behind genuine admission; DATA/DVC
  availability alone is never desktop authority.
- R6 must keep the existing WTS retirement and native-generation fences,
  `retireWithoutNativeInput()`, DXGI
  `Acquire → Map → Consume → Unmap → ReleaseFrame`, safe deferred COM teardown
  and no stale SendInput.

Windows App or `mstsc.exe` may still be used earlier as **clients** against an
authorized Linux server. That does not authorize this Windows native server.
