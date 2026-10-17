# Linux user-mode server test bundle (R5 → R9)

**Status: OFFLINE ONLY.** The existing `rdp-server` executable refuses
`serve`; the bundle is installable but cannot offer a real RDP desktop.
It is independent of the existing protocol SDK, whose CMake install/CPack
exports are unchanged.

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

Only after R10 supplies the real `serve --config` path, R3 supplies
authoritative graphics DATA and input, and the owner approves the exact
real seat0 host: copy the example to a separate
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

R10 must create exactly one `X11DesktopResources` via R2's synchronous
admitted-display visitor and own serialized logind/event loop; no second X11
runtime owner or configuration/`DISPLAY` fallback. R3 must provide
DATA_FIRST/DATA publication and complete immutable frame-to-outer-write
receipt mapping, plus fresh authorized decoded input. R5 retains synchronous
XShm→R4 borrowing, nonzero RandR/native generations and
`retireWithoutNativeInput()` on R2/R3 permission loss.

A real owner-approved physical Linux X11 seat0, genuine
Kerberos/CredSSP+PAM+NSS/logind, TLS identity and safely enabled listener
are **NOT AVAILABLE/NOT TESTED**. Human acceptance must separately log
versions and visible frame, pointer/keyboard, resize, logout, reconnect for
`mstsc.exe`, Windows App on Windows, and Windows App on macOS. No live
desktop/input test is authorized by this package.
