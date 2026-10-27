# macOS Windows App physical owner-evidence procedure

This is the reusable client-side evidence procedure for an owner-authorized
Windows App for macOS attempt against the Linux/X11 RDP-server host. It is
diagnostic only. It does not authorize a production protocol, certificate,
authentication, native Admission, MCS, Share, graphics, input or clipboard
change.

Microsoft documents Windows App for macOS logging through the application UI:
**Help -> Troubleshooting -> Logging**, choose Core/UI log levels and an output
folder, start logging, reproduce the issue, then stop logging. Use that supported
workflow. Do not guess or depend on a private Windows App log path.

Reference:
<https://learn.microsoft.com/windows-app/troubleshoot-collect-logs>

The current Windows App release history is published at:
<https://learn.microsoft.com/windows-app/whats-new>

## Non-negotiable safety boundary

- Do **not** add, remove, import, persist or otherwise change any macOS
  Keychain/trust-store certificate for this attempt.
- Do not disable certificate verification, Gatekeeper, macOS privacy controls
  or Windows App security policy.
- Never record the Session Password or the Windows App saved-credential
  password in the manifest, notes, command line or repository. The helper has
  no password argument.
- Do not use the Linux account password as the Windows App saved password unless
  the owner intentionally made that password identical to the independent
  RDP-server Session Password.
- If a certificate warning appears, record whether it appeared and whether the
  owner explicitly accepted that warning. Do not pre-trust the certificate to
  make the warning disappear.
- A server-side EOF after Type 2/Await-Type-3 is transport evidence only. It is
  **not** evidence that Windows App rejected the certificate or that the
  Session Password was wrong.
- Never commit the evidence manifest, captured client logs, usernames,
  credentials, NTLM challenge/response material, passwords, tokens or other
  owner-specific private evidence to this repository.

## Required credential-controlled next attempt

For the next physical qualification run, configure the Remote PC entry in
Windows App with an **explicit Saved credential selected**. That saved
credential must contain:

- **Username:** the exact Username shown/configured by RDP-server for this
  standalone credential;
- **Password:** the exact independent Session Password configured in
  RDP-server.

Treat those values as the two ends of the same standalone application
credential. Do not substitute the Linux account password unless the owner
intentionally chose the same secret for both. Record only whether the server
GUI credential and Windows App saved credential were intentionally matched;
never record the password itself.

A run using **Ask when required / none** or another credential state may still
be diagnostic, but it does not satisfy this credential-controlled next gate.

## Before the attempt

1. On the Linux server, begin the owner receipt with `git rev-parse HEAD`
   before build/test, as required by the Agent-9 owner-candidate gate. Record
   that exact 40-character SHA, then complete the canonical full CTest run and
   record its full result before starting the physical connection attempt.
2. On the Mac, close any active Windows App connection. Record the destination
   exactly as it will be entered; do not normalize an IP address, hostname,
   service prefix or whitespace after the attempt.
3. Record the Remote PC Saved credential state as exactly one of:
   `explicit-saved-selected`, `ask-when-required-or-none`, or `other`.
   When an explicit saved credential is selected, record its exact Username,
   whether it was newly created for this attempt, and whether its Username and
   password were intentionally matched to the RDP-server Username and Session
   Password. Do not record the password.
4. In Windows App choose **Help -> Troubleshooting -> Logging**. Record the
   exact Core log level and UI log level selected. Choose a fresh
   owner-controlled output folder for this attempt.
5. Select **Start Logging** before initiating the RDP connection and record
   that logging was started.
6. Do not change Keychain or certificate trust settings.

Microsoft's documented logging procedure intentionally lets the owner choose
the output folder, so this project does not rely on an undocumented client log
location.

## During and immediately after the same attempt

Record all of the following from that one attempt:

- full CTest result for the exact server SHA recorded before the attempt;
- Windows App version and build;
- exact destination string entered;
- whether an explicit Saved credential was selected (`yes`/`no`) and the
  typed Remote PC Saved credential state;
- exact Username entered in the saved credential, or `not-applicable` when no
  saved credential was selected;
- whether that credential was newly created for the attempt;
- whether the Windows App saved credential and RDP-server standalone credential
  were intentionally matched;
- whether a certificate warning appeared;
- if it appeared, whether the owner accepted it;
- exact client-side failure/error text, or the literal note `none shown`;
- exact attempt time with an explicit UTC offset;
- exact Core/UI log levels and whether Start Logging occurred before the
  attempt;
- the Windows App client-side log files produced by the selected logging
  folder, when available;
- the correlated Linux connection ID, Linux terminal-event timestamp with an
  explicit UTC offset, and complete Linux terminal failure record.

Immediately after the failure, return to **Help -> Troubleshooting -> Logging**
and select **Stop Logging**. Record that logging was stopped, preserve the
same-attempt output folder, and do not mix logs from a later retry into it.

## Read-only manifest helper

`scripts/macos_windows_app_owner_evidence.py` is deliberately read-only with
respect to the supplied application and log inputs. It:

- reads `Contents/Info.plist` only from the `.app` path explicitly supplied by
  the owner and records `CFBundleShortVersionString` + `CFBundleVersion`;
- records the typed Saved credential state, exact saved Username when
  applicable, newly-created yes/no state and intentional server/client match
  yes/no state, but has no password input or output;
- records whether logging was started before and stopped after the attempt;
- records an exact Linux connection ID plus offset-aware Linux terminal-event
  timestamp for same-attempt correlation;
- reads only the log directory explicitly supplied by the owner;
- rejects symlinks in that log tree;
- bounds the inventory to 256 regular files and 512 MiB total;
- records relative file names, byte counts and SHA-256 hashes, never log
  contents;
- writes the JSON manifest to standard output only;
- has no Keychain, trust-store, Windows App preference or network mutation.

Example, replacing every placeholder with values from the same attempt:

```sh
mkdir -p build/owner-evidence
python3 scripts/macos_windows_app_owner_evidence.py \
  --app "/actual/path/to/Windows App.app" \
  --server-sha "0123456789abcdef0123456789abcdef01234567" \
  --attempt-time "2026-10-27T05:30:00-07:00" \
  --destination "192.168.1.5" \
  --saved-credential-state explicit-saved-selected \
  --saved-credential-username "exact Username shown by RDP-server" \
  --saved-credential-newly-created yes \
  --server-client-credentials-intentionally-matched yes \
  --certificate-warning yes \
  --certificate-warning-accepted yes \
  --error-text "exact Windows App error text" \
  --core-log-level "level selected in Windows App" \
  --ui-log-level "level selected in Windows App" \
  --logging-started yes \
  --logging-stopped yes \
  --linux-connection-id "exact Linux connection ID" \
  --linux-terminal-time "2026-10-27T05:30:07-07:00" \
  --logs "/owner/chosen/windows-app-log-folder" \
  > build/owner-evidence/macos-windows-app-attempt.json
```

The application path above is an example argument, not a repository assumption.
Use the actual installed `.app` path. The helper does not discover or inspect
private application directories. There is intentionally no password argument.

If Windows App's supported logging control is unavailable or no log file is
produced, do not fabricate a path. Record the reason explicitly instead:

```sh
python3 scripts/macos_windows_app_owner_evidence.py \
  --app "/actual/path/to/Windows App.app" \
  --server-sha "0123456789abcdef0123456789abcdef01234567" \
  --attempt-time "2026-10-27T05:30:00-07:00" \
  --destination "192.168.1.5" \
  --saved-credential-state ask-when-required-or-none \
  --saved-credential-username not-applicable \
  --saved-credential-newly-created not-applicable \
  --server-client-credentials-intentionally-matched not-applicable \
  --certificate-warning no \
  --certificate-warning-accepted not-applicable \
  --error-text "exact Windows App error text" \
  --core-log-level "not recorded" \
  --ui-log-level "not recorded" \
  --logging-started no \
  --logging-stopped no \
  --linux-connection-id "exact Linux connection ID" \
  --linux-terminal-time "2026-10-27T05:30:07-07:00" \
  --logs-unavailable-reason "supported logging control unavailable or produced no file" \
  > build/owner-evidence/macos-windows-app-attempt.json
```

`--certificate-warning-accepted` must be `not-applicable` when no warning
appeared, and must be `yes` or `no` when a warning appeared. For
`ask-when-required-or-none`, the saved Username, newly-created state and
server/client match state must all be `not-applicable`. The attempt and Linux
terminal timestamps must both be ISO-8601 with explicit UTC offsets so the
manifest can emit UTC correlation values.

## Evidence bundle and interpretation

The owner evidence bundle consists of the manifest JSON, the original Windows
App log files from the selected output folder when available, and the complete
Linux terminal record from the same attempt. Review client logs before sharing
them outside the owner evidence channel; do not publish credentials, usernames
or private identifiers in Git.

The client log and exact UI error may identify a client credential/delegation
or policy boundary. In their absence, the server-side progression

`TLS -> Type 1 -> Type 2 fully committed -> Await-Type-3 -> EOF`

supports only the observed peer-close boundary. Because Type 3 was not
received, it does **not** demonstrate a wrong Session Password. It also does
not distinguish missing/unsaved credential material, client-side credential or
delegation policy, certificate/user policy, user cancellation or another
typed client-side failure. Production remains `fixed-name / RDP-SERVER` until
new external evidence authorizes a narrower change.
