## R7 temporary CLI Username and credential copy rules (2026-11-01)

The non-authorizing --username override uses R2-compatible bounded UTF-8:
reject path separators and C0/C1/DEL controls. Session Password remains
independent and permits ordinary punctuation. R7's Qt adapter also retires
its own temporary mutable UTF-16 password copy after R10's synchronous
credential handoff even if an implementation returns without clearing it.
No password persistence, auto-Sharing, new settings store, permission,
listener, native authority or Release credential gate changes.

## R7 restored rapid-test preferences integration (2026-11-01)

The portable desktop consumes R2's existing secure per-user non-secret
preferences API for explicitly edited Username, a freshly R10-approved stable
LAN interface ID, port, input and permission-lifetime controls. GUI supplies
no file path, duplicate store, saved address, password, permission or Sharing
state. Absent/invalid storage yields safe defaults; --username is process-only
until the owner explicitly edits Username. Stored stable IDs only select
current R10-approved choices; R10 alone authorizes Start after the owner's
explicit action. Offline fake-host tests inject memory-only R2 callbacks.
The Linux expert --config path remains outside ordinary preference loading.

## User-only preference storage and opt-in vault design (2026-11-01)

The per-user non-secret preferences are convenience values only: last **manually entered** Username, a stable LAN interface identifier requiring fresh re-enumeration, port, input preference and permission-lifetime preference. Loading cannot configure Session Password, open a listener, grant host consent/View/Input/Clipboard or change GraphicsReady. Startup remains Sharing OFF. Absent/invalid/unavailable secure storage yields defaults and no shared fallback.

Future opt-in native credential-vault support is **design only**: first require explicit owner approval to change the current `runtimeBootstrapMayPersist(SessionPassword)==false` policy, security review per Windows Credential Manager/DPAPI, macOS Keychain and supported Linux native secret service, consent UX with unchecked-by-default Save choice, unlock/expiry/revoke/delete, account/identity rotation, explicit unsupported-platform status and no plaintext fallback. Even a future vault can never grant native R2 admission or start Sharing automatically; no password persistence is implemented here.

## Rapid-test desktop CLI and settings boundary (2026-11-01)

The portable rdp-server-desktop accepts zero arguments for normal startup,
--username NAME for a validated non-authorizing per-process edit,
--password-stdin for a bounded non-echo redirected secret and --enable
solely to display the GUI Sharing confirmation. The owner must still
explicitly turn Sharing ON through the existing runtime-owned flow.
--help prints without QApplication or native runtime construction.
No command-line/environment password or automatic listener is allowed.
The Linux-only --config FILE expert option remains isolated.

R2 alone owns the secure per-user non-secret preferences API. The
ordinary portable GUI consumes that API, never persists Session Password
or Sharing ON, and revalidates saved interface IDs against freshly approved
R10 LAN enumeration. Stored fields never grant admission or permission.

## Remote RDP client credential guidance (2026-10-27)

The standalone Main credential surface must tell the owner that the displayed
Username and the owner-entered Session Password are the credentials to enter in
the remote RDP client. This is manual product guidance only: the server does not
send, synchronize or otherwise teach the Session Password to Windows App or
another client.

The Username remains a non-authorizing convenience value. Never retrieve or
auto-fill an operating-system password. After the Session Password has been
transferred into the runtime credential owner, keep the secret out of the GUI
editors and do not add a password-copy or password-reveal action. This guidance
does not diagnose a pre-Type-3 peer close as a bad password or grant native
Admission, MCS, Share, graphics, input or clipboard authority.

## Local Username convenience and credential separation (2026-10-24)

When a safe current interactive local account name is available, the desktop GUI
uses it only as the initial editable Username convenience value: effective local
account on Linux, console user on macOS, and interactive WTS process session on
Windows. Root/system/service identities are not suggested; failure to resolve a
safe name leaves Username empty rather than guessing an identity.

The server never retrieves or auto-fills the operating-system account password.
Session Password remains a separate application credential entered by the
owner, starts empty, and does not silently become OS authentication. A Username
suggestion never grants native admission or maps the remote credential to that
OS account.

## Normal portable application startup

The normal consumer entry point is `rdp-server-desktop` with no required
arguments. The intended product workflow is ZIP -> extract -> double-click ->
set Session Password -> explicitly turn Sharing ON -> connect over the private
LAN. Ordinary users must not create or understand `server.conf`, TLS/private
key files, RDP licensing key material, Kerberos/PAM provisioning, UID/seat/
display policy files or listener configuration. `--config` may remain an
explicit expert/legacy override, but it is not the product provisioning model.

Double-click may prepare private local runtime prerequisites, but it must never
open a network listener. R1 may bind only after the explicit Sharing action
and fresh endpoint/security/owner checks. GUI presentation qualification alone
does not establish this end-to-end product workflow.

# RDP-server — canonical project vision

## Mission

Build a fast, secure, interoperable, open-source **C++23 Remote Desktop
Protocol server** across Linux, macOS, Windows, BSD and other operating
systems, using a portable RDP core and replaceable OS integrations.

> RDP protocol first. Fast native C++23 implementation. No workarounds when a standards-compliant RDP mechanism already solves the problem.

## Product acceptance

- **Independence:** No runtime or build reliance on xrdp, VNC/RFB,
  patched chansrv or another RDP server. Historical sources are
  provenance, not protocol architecture.
- **Protocol:** Complete standards-compliant X.224/TPKT, MCS/GCC, TLS,
  CredSSP/NLA, licensing, capabilities, share activation, virtual
  channels, graphics, input and orderly disconnect/reconnect.
- **Security:** Explicit negotiated identity, independent OS session
  authorization, bounded untrusted input and deterministic cancellation.
- **Portability:** C++23 first-party wire/session core and separable
  capture, input, clipboard, credentials and platform session adapters.
- **Usability:** Windows and macOS clients and FreeRDP clients can connect
  securely and use a real desktop with graphics, input and CLIPRDR
  text, PNG/DIB and standard file clipboard. No mandatory FUSE mounts.
- **Efficiency:** Low CPU, RAM, bandwidth and tail latency on old
  hardware; scalar baseline, measured optional acceleration.
- **Sustainability:** One state-machine owner, shared reusable tests,
  one reusable build root and minimal duplicated documentation.

## Current truthful status (October 14, 2026)

A subset of first-party C++23 files is migrated and a portable static
protocol library passes historical cross-platform tests. It is **not**
an authenticated or installable standalone RDP server. The full former
project was not migrated, and its automated source-import workflow has
been retired. Do not mistake green protocol unit tests for client
acceptance, real desktop admission or performance.

## Execution model

Implement a bounded client-facing RDP connection state machine, authenticated
session and channel lifecycle, then graphics/input/clipboard integrations
and OS adapters. Accept each milestone only with negative tests and
appropriate real-client evidence. No production access from synthetic
security fixtures.

The one living TODO is [docs/ROADMAP.md](ROADMAP.md).
Mandatory standards:
[coding](coding_standards.md), [testing](testing_standards.md),
[compilation](compile.md), [benchmarks](benchmark.md).
All agents follow [AGENTS.md](../AGENTS.md) on every task.

## Personal desktop admission mode

The selected near-term product mode is one personal desktop reached by
Microsoft Windows App or Windows 11 `mstsc.exe`. This mode does **not** depend
on an RD Licensing CAL decision. That removes a licensing gate only; it does
not weaken authentication or native desktop admission. Every desktop access
must still bind the exact TLS/CredSSP authenticated identity to independently
verified native OS login/session evidence and a revocable R2 lifetime before
R3 Share/graphics/input/clipboard can consume it.
