# macOS protocol TEST BUNDLE (R7; non-serving)

This deliberately installs the **protocol SDK only**. No runnable native macOS
RDP server, AppKit application, listener, ScreenCaptureKit provider or Quartz
injector is shipped. It must never be advertised as an interactive server or a
universal binary. R2 authenticated-UID lease, R10 AppKit session-watch owner
and R3 Graphics DATA/input composition remain BLOCKED.

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

Optional future GUI-user lifecycle is **disabled / not installed**. Do not
load a LaunchAgent until R10 supplies an authenticated per-user foreground
executable and lifecycle handshake. At that point an opt-in user LaunchAgent
must have `RunAtLoad=false`, `KeepAlive=false`, a fixed absolute program
path and a validated per-user label, with explicit owner `bootstrap`,
`bootout`, status and uninstall operations. Reject extra keys and external
program paths; never use a LaunchDaemon, implicit installer bootstrap or
automatically open Screen Recording/Accessibility prompts.

Screen Recording and Accessibility are separate **operation-specific**
prerequisite observations, neither authentication nor R2 admission. Only R2 may
mint the genuinely authenticated macOS UID/session lease; R10 must serialize
the AppKit watch, retire capture on authority loss and call
`retireWithoutNativeInput()` before any Quartz teardown. Existing
synchronous CoreVideo borrowed pixel lifetime remains unchanged.
