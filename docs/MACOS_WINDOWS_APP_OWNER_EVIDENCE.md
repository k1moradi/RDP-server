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
- If a certificate warning appears, record whether it appeared and whether the
  owner explicitly accepted that warning. Do not pre-trust the certificate to
  make the warning disappear.
- A server-side EOF after Type 2/Await-Type-3 is transport evidence only. It is
  **not** evidence that Windows App rejected the certificate.
- Never commit captured client logs, credentials, NTLM challenge/response
  material, passwords, tokens or owner-specific private evidence to this
  repository.

## Before the attempt

1. On the Linux server, begin the owner receipt with `git rev-parse HEAD`
   before build/test, as required by the Agent-9 owner-candidate gate. Record
   that exact 40-character SHA.
2. On the Mac, close any active Windows App connection. Record the destination
   exactly as it will be entered; do not normalize an IP address, hostname,
   service prefix or whitespace after the attempt.
3. In Windows App choose **Help -> Troubleshooting -> Logging**. Record the
   exact Core log level and UI log level selected. Choose a fresh
   owner-controlled output folder for this attempt.
4. Select **Start Logging** before initiating the RDP connection.
5. Do not change Keychain or certificate trust settings.

Microsoft's documented logging procedure intentionally lets the owner choose
the output folder, so this project does not rely on an undocumented client log
location.

## During and immediately after the same attempt

Record all of the following from that one attempt:

- Windows App version and build;
- exact destination string entered;
- whether a certificate warning appeared;
- if it appeared, whether the owner accepted it;
- exact client-side failure/error text, or the literal note `none shown`;
- approximate attempt time with an explicit UTC offset;
- the Windows App client-side log files produced by the selected logging
  folder, when available;
- the complete correlated Linux terminal failure record.

Immediately after the failure, return to **Help -> Troubleshooting -> Logging**
and select **Stop Logging**. Do not mix logs from a later retry into the same
evidence folder.

## Read-only manifest helper

`scripts/macos_windows_app_owner_evidence.py` is deliberately read-only with
respect to the supplied application and log inputs. It:

- reads `Contents/Info.plist` only from the `.app` path explicitly supplied by
  the owner and records `CFBundleShortVersionString` + `CFBundleVersion`;
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
  --certificate-warning yes \
  --certificate-warning-accepted yes \
  --error-text "exact Windows App error text" \
  --core-log-level "level selected in Windows App" \
  --ui-log-level "level selected in Windows App" \
  --logs "/owner/chosen/windows-app-log-folder" \
  > build/owner-evidence/macos-windows-app-attempt.json
```

The application path above is an example argument, not a repository assumption.
Use the actual installed `.app` path. The helper does not discover or inspect
private application directories.

If Windows App's supported logging control is unavailable or no log file is
produced, do not fabricate a path. Record the reason explicitly instead:

```sh
python3 scripts/macos_windows_app_owner_evidence.py \
  --app "/actual/path/to/Windows App.app" \
  --server-sha "0123456789abcdef0123456789abcdef01234567" \
  --attempt-time "2026-10-27T05:30:00-07:00" \
  --destination "192.168.1.5" \
  --certificate-warning no \
  --certificate-warning-accepted not-applicable \
  --error-text "exact Windows App error text" \
  --core-log-level "not recorded" \
  --ui-log-level "not recorded" \
  --logs-unavailable-reason "supported logging control unavailable or produced no file" \
  > build/owner-evidence/macos-windows-app-attempt.json
```

`--certificate-warning-accepted` must be `not-applicable` when no warning
appeared, and must be `yes` or `no` when a warning appeared. The timestamp must
be ISO-8601 with an explicit UTC offset so the manifest can also emit UTC for
Linux-log correlation.

## Evidence bundle and interpretation

The owner evidence bundle consists of the manifest JSON, the original Windows
App log files from the selected output folder when available, and the complete
Linux terminal record from the same attempt. Review client logs before sharing
them outside the owner evidence channel; do not publish credentials or private
identifiers in Git.

The client log and exact UI error may identify a client policy boundary. In
their absence, the server-side progression

`TLS -> Type 1 -> Type 2 fully committed -> Await-Type-3 -> EOF`

supports only the observed peer-close boundary. It does not distinguish
certificate policy, target identity, authentication-mechanism policy, user
cancellation or another client-side failure. Production remains
`fixed-name / RDP-SERVER` until new external evidence authorizes a narrower
change.
