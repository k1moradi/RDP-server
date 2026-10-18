# Linux user-mode server test bundle (R5 → R9)

**Status: STARTUP-DISABLED PREVIEW / NO LIVE DESKTOP AUTHORITY.** Linux now
has an explicit `serve --config FILE` path, but it is loopback-only. R10 now
passes accepted sockets to the serialized R1 TLS/CredSSP/R2 admission path;
without genuine R2 authority it fails closed, and even an admitted connection
is retired after the R2-authorized MCS Connect Response pending production
Erect Domain, AttachUser, ChannelJoin and Client Info composition. The bundle installs no enabled service or
autostart and cannot offer a real RDP desktop. It remains independent of
the protocol SDK, whose CMake install/CPack exports are unchanged.

## R9 common SERVER-TEST relationship

R5's Linux-specific installer/service template is now an input to R9's
cross-platform SERVER-TEST assurance, not a replacement artifact. The common
Linux preview is named
`rdp-server-test-<version>-linux-<architecture>-<short-sha>.zip`, contains the
same actual built `rdp-server`, includes this disabled R5 user-service template,
and records the dependency closure actually resolved on the hosted build plus
internal/outer SHA-256. R9's extracted-binary smoke verifies offline CLI/config
behavior, bare-startup refusal, and that the packaged syntax-only sample also
fails closed under `serve --config`. The three-platform R9 aggregate now
requires every expected smoke-check field to be present and exactly PASS;
missing/failed/unreviewed checks cannot hide behind a top-level PASS. The R5
installer remains the Linux-native install manifest; neither path enables systemd or claims live M3.


## R9 package and integrity

Build the actual `rdp-server` executable inside the one `build/` root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --config Debug --parallel 2
python3 packaging/linux/server_test_bundle.py bundle \
  --executable build/rdp-server --source-sha "$(git rev-parse HEAD)" \
  --version 0.1.0 --output build/rdp-server-linux-test.zip
sha256sum build/rdp-server-linux-test.zip
ldd build/rdp-server
```

ZIP members: `bin/rdp-server` (real compiled executable),
`systemd/rdp-server-test.service`, `config/server.conf.example`,
`manifest.json` (source SHA, version, file sizes/SHA-256, dependency
allowlist). R9 must attach the whole-ZIP SHA and actual `ldd` dependency
closure; any `not found` fails. Accept only system glibc/libstdc++,
OpenSSL, GSSAPI/Kerberos, PAM, libsystemd and XCB/X11/XTEST where actually
linked, plus audited platform transitive dependencies. Do not imply these
optional libraries are all linked or bundle privileged or secret material.

## Install / verify / remove, with no service activation

Run as the intended ordinary graphical desktop user:

```sh
python3 packaging/linux/server_test_bundle.py install --bundle build/rdp-server-linux-test.zip
python3 packaging/linux/server_test_bundle.py verify --bundle build/rdp-server-linux-test.zip
python3 packaging/linux/server_test_bundle.py uninstall --bundle build/rdp-server-linux-test.zip
```

The installer copies to user-owned
`~/.local/share/rdp-server-test/bin/rdp-server` (0700),
`~/.config/systemd/user/rdp-server-test.service` (0600), and
`~/.config/rdp-server-test/server.conf.example` (0600); private
product subdirectories are 0700. Existing targets and symlinks are rejected.
Modified files prevent removal to avoid destroying user edits. No
`systemctl`, network, desktop capture, XTEST, login activation or
`DISPLAY` selection is performed.

## Future explicitly authorized service lifecycle (NOT YET ALLOWED)

Only after R10 composes the remaining Erect Domain, AttachUser,
ChannelJoin and Client Info writers, R1/R2 review the completed connection,
R10 binds R3's fresh-authority decoded input route to an admitted R5 desktop,
and the owner approves
the exact real seat0 host: copy the example to a separate
`~/.config/rdp-server-test/server.conf` owned by the desktop account,
mode 0600. Provision genuine TLS certificate/private key and GSS
service identity/keytab separately in restricted private paths, plus
R2's authenticated PAM/NSS/logind/Kerberos seat and display policy.
Never put secrets in arguments, environment, logs, artifacts or CMake
caches. The unit is disabled by default, tied to
`graphical-session.target` and requires an explicit human authorization
marker. Do not use `loginctl enable-linger` or a privileged daemon.
Confirm that the desktop actually manages `graphical-session.target`;
do not replace it with an unscoped login target.

After the human gate:

```sh
chmod 600 ~/.config/rdp-server-test/server.conf
~/.local/share/rdp-server-test/bin/rdp-server --check-config ~/.config/rdp-server-test/server.conf
~/.local/share/rdp-server-test/bin/rdp-server --check-tls-credentials ~/.config/rdp-server-test/server.conf
~/.local/share/rdp-server-test/bin/rdp-server --check-linux-security ~/.config/rdp-server-test/server.conf
systemctl --user daemon-reload
systemctl --user status graphical-session.target
touch ~/.config/rdp-server-test/authorized
chmod 600 ~/.config/rdp-server-test/authorized
systemctl --user enable rdp-server-test.service
systemctl --user start rdp-server-test.service
systemctl --user status rdp-server-test.service
systemctl --user stop rdp-server-test.service
systemctl --user disable rdp-server-test.service
rm ~/.config/rdp-server-test/authorized
systemctl --user daemon-reload
```

Before uninstall stop and disable; manually remove the separately created
`server.conf` and authorization marker, then invoke `uninstall`.
Never treat successful offline preflight as authorization to listen.

## M3 — BLOCKED

R10 has connected the accepted socket to serialized `LinuxRuntimeConnection`
TLS/CredSSP and first admitted MCS Connect Initial; it must complete the
production MCS writers, then create exactly one `X11DesktopResources` via
R2's synchronous admitted-display visitor and own the serialized logind/event loop; no second X11 runtime owner or
configuration/`DISPLAY` fallback. R3 DATA_FIRST/DATA publication and immutable
frame-to-outer-write receipt mapping are now present; the remaining R3 live
gate is fresh-authority decoded input. R5 retains synchronous
XShm→R4 borrowing, nonzero RandR/native generations and
`retireWithoutNativeInput()` on R2/R3 permission loss.

A real owner-approved physical Linux X11 seat0, genuine
Kerberos/CredSSP+PAM+NSS/logind, TLS identity and safely enabled listener
are **NOT AVAILABLE/NOT TESTED**. Human acceptance must separately log
versions and visible frame, pointer/keyboard, resize, logout, reconnect for
`mstsc.exe`, Windows App on Windows, and Windows App on macOS. No live
desktop/input test is authorized by this package.
