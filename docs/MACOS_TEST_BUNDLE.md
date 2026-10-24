# macOS protocol TEST BUNDLE (R7; non-serving)

## R7 LaunchAgent render-location guard (2026-10-18)

The optional offline LaunchAgent renderer resolves existing symlinked output
parents before checking registration boundaries. It refuses **any** output
inside the resolved `~/Library/LaunchAgents` directory, including alternate
filenames, nested paths and symlink aliases; it still renders only a manually
reviewed inert Aqua plist outside that location. The existing LaunchAgent
unit test includes denials for those paths. This guards against implicit
registration; it does not add a launchctl call, TCC prompt, runtime listener,
desktop capture or Quartz posting. This source-level fix awaits its own
exact-branch CI result and does not replace owner macOS 27 M1 evidence.

This deliberately installs the **protocol SDK only**. No runnable native macOS
RDP server, AppKit application, listener, ScreenCaptureKit provider or Quartz
injector is shipped. It must never be advertised as an interactive server or a
universal binary. The source tree now contains R2's authenticated native
authorization seam and R5's authorization-bound native desktop aggregate, but
neither changes this artifact: R10 product composition, R3 DATA/input delivery
and owner-authorized live acceptance remain separate gates.

## Relationship to R9 SERVER-TEST previews

This R7 artifact remains **protocol-only** and is never renamed into the server
family. R9 separately builds
`rdp-server-test-<version>-macos-<architecture>-<short-sha>.zip` from the
actual current `rdp-server` executable. That executable preview is also
startup-disabled and uses an extraction-only manifest under a distinct
`server-test` location. Exact head `9a2d09968e741d13bc1c5e76753ecaf1be7557ef`
has green primary Actions `39066363832` and structure Actions `39066363884`:
hosted macOS passes **546/546 Debug + 546/546 Release**, the dedicated R7
lifecycle job passes **21/21 Debug + 21/21 Release**, the authority-loss input
sanitizer selector passes **2/2**, and R9 produced the actual single-slice
`rdp-server-test-0.1.0-macos-arm64-9a2d09968e74` startup-disabled preview.
Artifact presence remains package/CLI evidence only, not owner macOS 27 or
native admission acceptance.


## Hosted release inputs and verification

The `protocol` macOS Actions matrix job builds Release on `macos-latest`
and installs to `build/stage`. Only its actual static archive slice is accepted:
`lipo -archs` must return **one** of `arm64` or `x86_64`; a
multi-slice, mixed or unknown archive fails packaging. The output name includes
the detected architecture, source SHA and project version. Inspect
`manifest.json` for exact commit SHA, version, arch, minimum macOS CI host floor (conservative, not a verified deployment target),
runtime declaration, per-file SHA-256 and license declaration. The adjacent
`.sha256` records the outer ZIP checksum. CI must not claim macOS 27
owner-native validation from its hosted macOS image.

This is a development **unsigned test artifact**. LICENSE, NOTICE and
third-party attribution are copied from the CMake stage. No fabricated Apple
Developer ID or notarization claim is made; Gatekeeper remains fully operative.
Do not remove quarantine or bypass OS verification. A future redistributable
`.app` requires the stable reverse-DNS bundle ID, fixed executable identity,
hardened-runtime entitlements reviewed for capture/input, reproducible code
resources and dependency embedding, a private owner-controlled Developer ID
Application signing identity, notarization submission and stapling verification.
Signing identity, team ID and notarization credentials are not CI defaults.

## Per-user manual lifecycle

For an explicitly downloaded and verified test ZIP on the matching Mac:

```sh
python3 scripts/macos_test_bundle.py install --archive /path/to/rdp-server-macos-protocol-test-ARCH-SHA.zip
python3 scripts/macos_test_bundle.py status
python3 scripts/macos_test_bundle.py remove
```

The predictable path is
`~/Library/Application Support/RDP-server/test-bundle/`. Install is
idempotent for byte-identical content, refuses mismatching/modified installs,
and never starts a process. `status` describes installation, **not** running
server status. **Start: unavailable**, because there is no admitted runtime
executable. **Stop: not applicable**; no background process is installed.
`remove` only deletes an identified test-bundle directory. Non-secret config
template for future admitted runtime: `mode = "PersonalDesktop"`,
`listener_enabled = false`, `native_capture_enabled = false`,
`native_input_enabled = false`. It is documentation, not a recognized runtime
configuration schema.

The R9 macOS SERVER-TEST preview now carries
`tools/macos_test_launch_agent.py` as an **optional disabled-by-default**
GUI-user configuration helper. It renders label
`org.rdpserver.server-test` only for the fixed absolute executable path
`~/Library/Application Support/RDP-server/server-test/bin/rdp-server`.
The plist is Aqua-only with `RunAtLoad=false` and `KeepAlive=false`; unknown
keys, alternate executable paths, socket/MachService triggers, root homes and
direct rendering into `~/Library/LaunchAgents` are denied. The helper does
not execute `launchctl`, open sockets, request TCC, capture pixels or inject
input.

Render and validate to a review location, then install/register it only by
explicit owner action:

```sh
server_root="$HOME/Library/Application Support/RDP-server/server-test"
cd "$server_root"
python3 tools/macos_test_launch_agent.py render --home "$HOME" \
  --output ./org.rdpserver.server-test.plist
python3 tools/macos_test_launch_agent.py validate --home "$HOME" \
  --plist ./org.rdpserver.server-test.plist

mkdir -p "$HOME/Library/LaunchAgents"
install -m 600 ./org.rdpserver.server-test.plist \
  "$HOME/Library/LaunchAgents/org.rdpserver.server-test.plist"
launchctl bootstrap "gui/$(id -u)" \
  "$HOME/Library/LaunchAgents/org.rdpserver.server-test.plist"
launchctl print "gui/$(id -u)/org.rdpserver.server-test"
```

`bootstrap` only registers this no-trigger job. **Manual start remains
non-serving today**: `launchctl kickstart -k
"gui/$(id -u)/org.rdpserver.server-test"` reaches the current
`rdp-server serve` refusal and exits without a listener. Once R2/R10/R3
secure startup exists, the same explicit kickstart is the intended foreground
GUI-user activation point. Stop with `launchctl kill SIGTERM
"gui/$(id -u)/org.rdpserver.server-test"`; uninstall with `launchctl bootout
"gui/$(id -u)" "$HOME/Library/LaunchAgents/org.rdpserver.server-test.plist"`,
remove that plist, then remove only the verified SERVER-TEST directory.
Never use a LaunchDaemon, `sudo`, implicit installer bootstrap or automatic
Screen Recording/Accessibility prompts.

Screen Recording and Accessibility are separate **operation-specific**
prerequisite observations, neither authentication nor R2 admission. Only R2 may
mint the authenticated-session proof. `ExistingOsAccount` must still match its
authenticated UID to the current console UID, but `StandalonePassword` binds
the exact authenticated application session and does not fabricate or require a
remote macOS UID. The console/audit/SecuritySession UID data remains fresh local
desktop target evidence in either case. R10 must serialize the AppKit watch,
retire capture on authority loss and call `retireWithoutNativeInput()` before
any Quartz teardown. Existing synchronous CoreVideo borrowed pixel lifetime
remains unchanged.
