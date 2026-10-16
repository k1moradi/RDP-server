## R8 Windows completed-file CF_HDROP build boundary (2026-10-16)

No new library or package is added. The existing cross-platform `rdp-server-windows-clipboard` target compiles the completed-file state and bounded DROPFILES serializer everywhere; `_WIN32` continues to compile the real `GlobalAlloc(GMEM_MOVEABLE)`/`SetClipboardData` bridge and link the existing `user32` dependency.

The existing `test_windows_clipboard_file_destination` executable gains `clipboard.windows-completed-file-hdrop-handoff`, so Linux/macOS exercise the portable ownership/serialization state with injected callbacks and Windows also compiles the native branch. R9 already builds this executable before `ctest -L clipboard`; its fail-closed registry preflight now requires the new handoff case. The installed portable SDK remains unchanged.

## R8 macOS file-descriptor destination build boundary (2026-10-16)

The existing noninstalled `rdp-server-macos-clipboard` target now also
compiles `src/platform/macos/mac_clipboard_file_destination.cpp` on every CI
OS. Portable state uses an injected native operation seam; Apple alone compiles
the guarded POSIX descriptor callbacks. No new framework or external package is
required and the installed portable protocol SDK remains unchanged.

`test_macos_clipboard_file_destination` likewise builds on every hosted OS.
Three injected behaviors run everywhere; Apple additionally registers the real
native descriptor case. The R9 Linux/Clang sanitizer job explicitly builds this
target before the shared `ctest -L clipboard` selection, so the portable
state remains sanitizer-covered even though real POSIX callbacks are exercised
only on Apple.

## R8 Windows file destination build boundary (2026-10-16)

`src/windows/windows_clipboard_file_destination.cpp` is part of the existing
noninstalled `rdp-server-windows-clipboard` target. Its receipt/progress state
and injected operation seam compile on every hosted CI OS; the real HANDLE
callbacks compile only under `_WIN32` and add no new external dependency.

`test_windows_clipboard_file_destination` likewise builds on every hosted OS
for deterministic state-machine coverage. Windows registers one additional
real-HANDLE build-root file case. The R9 Linux sanitizer compile list names the
target explicitly before `ctest -L clipboard`. The portable installed SDK
does not export the Windows native header.

## R8 completed-file X11 handoff build boundary (2026-10-16)

The existing Linux-only `rdp-server-linux-x11-clipboard` target now links the
existing noninstalled `rdp-server-linux-clipboard-file-destination` target so
its production XCB owner can consume completed descriptor materializations.
No new package is required beyond the XCB dependency already needed by that
adapter; no D-Bus, GLib/GIO, FUSE or xdg-desktop-portal development dependency
is introduced.

The existing `test_x11_clipboard_adapter` executable gains the dedicated
`clipboard.x11-completed-file-uri-handoff` case and continues to run through
the central clipboard label. R9 already builds both the X11 clipboard and
Linux file-destination test targets before `ctest -L clipboard`, so no
second sanitizer workflow or build root is added. The portable installed SDK,
macOS and Windows target graphs remain unchanged.

## R8 Linux file-descriptor destination build boundary (2026-10-16)

Linux builds the noninstalled
`rdp-server-linux-clipboard-file-destination` target from
`src/platform/linux/linux_clipboard_file_destination.cpp`. It links only the
existing portable protocol target and libc/POSIX syscalls already provided by
the platform; no XCB, FUSE, desktop-portal, D-Bus or file-manager development
package is required.

The corresponding `test_linux_clipboard_file_destination` target is
Linux-only and uses ordinary files under the existing CTest build-root working
directory. The R9 Linux/Clang sanitizer job explicitly builds it before the
shared `ctest -L clipboard` selection. The new platform header remains
noninstalled; the portable SDK and macOS/Windows builds do not gain a Linux
native file-destination API.

## R8 macOS clipboard adapter build boundary (2026-10-16)

The noninstalled `rdp-server-macos-clipboard` target compiles its portable
C++ ownership state on every CI OS, linking only the existing protocol target.
On Apple, the existing Objective-C++ language enablement additionally compiles
`mac_clipboard_adapter.mm` with ARC and links AppKit/Foundation. This target
is deliberately separate from `rdp-server-macos-capture`; Linux/Windows and
the installed protocol SDK gain no AppKit or ScreenCaptureKit dependency.

`test_macos_clipboard_adapter` is likewise compiled on every hosted OS with
synthetic native callbacks. The R9 Linux sanitizer build names that target
explicitly before selecting all clipboard-labelled CTests. The owner's normal
single `~/rdp-server/build` command is unchanged. Hosted Apple compilation
proves the dormant AppKit bridge builds, not that a live pasteboard was read or
written.

## R8 Windows clipboard adapter build boundary (2026-10-16)

The noninstalled `rdp-server-windows-clipboard` target compiles the
production clipboard state machine on every CI OS so its injected lifetime
logic receives broad warning/test coverage. Only `_WIN32` compiles the
dormant User32/GlobalAlloc callback bridge, linking `user32`; Linux/macOS
gain no Windows headers or native runtime dependency. The target links the
existing portable protocol library for `RemoteTransfer` and is not exported
or packaged in the SDK.

`test_windows_clipboard_adapter` uses synthetic native callbacks and never
opens the host clipboard. The owner's normal single `~/rdp-server/build`
command is unchanged; Windows/MSVC and owner MSYS2 CLANG64/Clang23 remain
separate compiler evidence for the native branch.

## R10 Linux explicit service-keytab provisioning (2026-10-16)

The pre-listener Linux runtime security component is currently built only when
the existing `RDP_SERVER_TEST_LINUX_GSSAPI=ON` gate is enabled. This keeps
MIT GSS/Kerberos out of the portable SDK and non-Linux builds while R10
validates the runtime composition. Linux CI already enables that gate for
Debug.

A configured keytab URI must be `FILE:/absolute/path`. R10 opens the path
component-by-component without following symlinks and requires a nonempty
regular file owned by the effective uid with no group/other permissions.
After opening, the runtime retains the descriptor and configures MIT GSS via
`FILE:/proc/self/fd/<n>`; the original pathname is not trusted again for
connection acceptors.

When built with the Linux GSS gate, `rdp-server --check-linux-security FILE`
accepts the original seven runtime fields plus these eight all-or-none fields:

```text
gss_service_principal=TERMSRV/rdp.example.test@EXAMPLE.TEST
gss_keytab=FILE:/absolute/private/service.keytab
authorized_kerberos_principal=alice@EXAMPLE.TEST
authorized_unix_account=alice
authorized_seat=seat0
authorized_display=:0
authorized_uid=1001
authorized_permissions=7
```

The command also validates the configured TLS server context and confirms that
the explicit GSS acceptor credential can be acquired. It does not need a
client ticket or KDC for that acquisition and it does not start a listener,
authenticate a client or grant OS/session access. Ordinary non-GSS builds keep
the prior CLI surface unchanged.

Default Linux CTests create only synthetic keytab material under
`build/runtime-linux-security-fixtures/`; no host keytab or ticket cache is
read. Production service/keytab installation permissions and lifecycle remain
a later R10 release/service gate.

# Compile standards — one persistent and reusable build directory

## R6 native Windows SendInput build note (2026-10-16)

The existing Windows-only `rdp-server-windows-desktop` target now also
compiles `windows_input_controller.cpp`. The Win32 translation compiles
against `user32!SendInput`, so no new library or package is required beyond
the target's existing `user32` linkage. Its callback factory remains
unexported until genuine R2/R3 Windows admission is available. Ordinary CTests
use the injected
callback seam and never call `SendInput`; no service permission, interactive
desktop, credentials or additional build option is required. Windows/MSVC and
owner MSYS2 CLANG64/Clang23 remain required compiler evidence.


## R6 DXGI pointer-shape build note (2026-10-16)

The noninstalled Windows-only `rdp-server-windows-desktop` target now also
compiles `windows_dxgi_pointer_shape.cpp`. It uses
`IDXGIOutputDuplication::GetFramePointerShape` through the SDK `dxgi`
library already linked for Desktop Duplication; there is no new package,
import library, CMake option or build root. Ordinary CTests use injected
callbacks and do not require a logged-in desktop. Hosted Windows/MSVC and
the owner's MSYS2 CLANG64/Clang23 remain separate compiler gates.





## R6 native Desktop Duplication build note (2026-10-16)

The existing Windows-only `rdp-server-windows-desktop` target now also
compiles `windows_dxgi_duplication_owner.cpp` under the ordinary
project command. It reuses SDK `d3d11` and `dxgi` libraries already
linked by that target; no new package, build directory, test option or
service permission is required. Native resource creation is never run
by default CTests; Windows/MSVC and owner MSYS2 CLANG64/Clang23 both
remain required independent compiler evidence.


**Mandatory:** Follow [AGENTS.md](../AGENTS.md), [VISION.md](VISION.md),
[testing_standards.md](testing_standards.md) and the living
[roadmap/TODO](ROADMAP.md). New verified compilation lessons
belong here rather than in additional build guides.

## Strict local directory contract

The only developer-machine checkout is **`~/rdp-server/`**.
The **single persistent build directory** is
**`~/rdp-server/build/`**, reused by every agent and every task.
Keep all objects, binaries, generated tests, sanitizer outputs, profiles
and logs within it. Nested output directories are allowed *inside*
that root, but never `build-debug`, `build-release`,
`cmake-build-*`, `tests/build`, or /tmp compilation roots.
Never routinely destroy the build cache or another agent's work.
CMake enforces `CMAKE_BINARY_DIR == <checkout>/build` and, outside
GitHub-hosted CI, requires the checkout itself at `~/rdp-server`.
The `GITHUB_ACTIONS=true` CI environment allows a hosted ephemeral
workspace but does not allow another build directory within that checkout.

GitHub-hosted CI cannot persist the owner's home checkout across jobs,
so **each isolated job** uses exactly one ephemeral
`<checkout>/build` and does not commit its output.

## Linux-only first-party XCB connection dependencies (R5)

If pkg-config finds both `xcb` and `xcb-randr`, the default Linux
CMake build compiles `rdp-server-x11-connection` and registers
`x11.display-event-budget-and-readiness`. Debian/Ubuntu provide the
native headers and linkage via `libxcb1-dev` and
`libxcb-randr0-dev`; the existing Linux CI job installs both.
The ordinary owner CMake/CTest one-liner is unchanged. If those
optional native development packages are missing, configure logs
that the native target and its CTest are not compiled/run; do NOT
report native PASS from headless helper checks. Windows/macOS and
the portable protocol library never require XCB. No display server,
credentials or live desktop are required for the native fixture.

## Linux native XShm capture dependencies (R5)

When pkg-config discovers both `xcb` and `xcb-shm`, Linux builds the
noninstalled `rdp-server-linux-xshm` target from the real
`x11_shared_memory_capture.cpp`. Debian/Ubuntu provide these headers and
libraries through `libxcb1-dev` and `libxcb-shm0-dev`, already provisioned
by hosted Linux CI. The ordinary
`x11.capture-native-disconnect-cancellation` case remains headless and starts
from a failed XCB descriptor. When `xvfb-run` is available, the same
production-linked executable also registers
`x11.capture-native-destructor-retirement` against a 1280x720x24 ephemeral
synthetic display. It performs a real MIT-SHM attach/capture, destructor
retirement, same-owner replacement, successful explicit disconnect, and a
second replacement generation. No logged-in desktop or credentials are used.
Missing native development files or Xvfb make only the corresponding optional
cases **NOT RUN**, never PASS. The one-root build command and portable SDK are
unchanged.

## Linux native XFixes cursor development dependencies (R5)

When `pkg-config` discovers both `xcb` and `xcb-xfixes`, the
Linux build compiles `rdp-server-linux-xfixes-cursor` from actual
`x11_cursor_tracker.cpp` and `cursor_image_conversion.cpp`.
On Debian/Ubuntu, install `libxcb1-dev` and
`libxcb-xfixes0-dev`; the existing GitHub Actions Linux job
provisions both. Native case
`x11.cursor-native-connection-denials-and-cancellation` remains headless.
When `xvfb-run` is available, the same production-linked executable also
registers `x11.cursor-native-destructor-retirement` against an ephemeral
synthetic display; it changes only that Xvfb root cursor and verifies XFixes
notification retirement while the borrowed XCB owner stays alive. Absence of
the development headers means native source/test NOT RUN, not PASS; absence of
Xvfb means only the synthetic-display retirement case is NOT RUN. No live
desktop or credentials are required. The owner's single `build/` command
and portable SDK remain unchanged.

## Linux-only native XDamage dependencies (R5)

The first-party `rdp-server-linux-xdamage` target is built when
`pkg-config` finds `xcb` and `xcb-damage`. Debian/Ubuntu
development packages: `libxcb1-dev` and `libxcb-damage0-dev`.
Linux hosted CI installs them. The target compiles the actual
`src/x11/x11_damage_tracker.cpp` plus the existing bounded
`src/core/damage_region.cpp`, with strict C++23 warnings. Its
headless `x11.damage-native-connection-denials-and-cancellation`
CTest requires no X server. When `xvfb-run` is available, the same
production-linked executable also registers
`x11.damage-native-destructor-retirement` against an ephemeral synthetic
display and proves the server-side Damage resource is retired while the
borrowed owner remains alive. If headers/libs are unavailable, these native
cases are not built and must be marked NOT RUN (not PASS); without Xvfb only
the synthetic-display retirement case is NOT RUN. No logged-in session, live
capture or credentials are required. The owner's existing one-root
configure/build/CTest command is unchanged, and XCB remains excluded from
installed portable protocol headers.

## Linux native XTEST and one-XCB owner dependencies (R5)

The XTEST controller needs `libxcb1-dev` plus `libxcb-xtest0-dev`.
Its headless denial/cancellation CTest still uses only a failed XCB descriptor.
When `xvfb-run` is present, `x11.input-native-destructor-held-input-release`
uses only an ephemeral synthetic X server: it holds one key and button through
the production XTEST controller, proves native state is down, destroys the
controller and requires both states to be released while the same XCB owner
stays healthy. This is lifecycle evidence, not authenticated desktop/input
acceptance.
With XCB/RandR, XShm, XFixes, XDamage and XTEST targets all available, CMake
also builds noninstalled `rdp-server-linux-x11-desktop`. The
`x11.desktop-resource-owner-connection-denial` CTest needs no X server.
When `xvfb-run` is present, CTest additionally registers
`x11.desktop-resource-owner-lifecycle`,
`x11.desktop-resource-event-routing`,
`x11.desktop-resource-randr-rebuild`, and
`x11.display-event-failure-defers-owner-teardown` against an ephemeral
1280x720x24 Xvfb server. The lifecycle case adds Xvfb `-noreset` because it
intentionally closes the last XCB client between independent owner generations;
that keeps the synthetic server stable while R5 teardown/recovery is tested.
The routing case generates a real XDamage notification only on that synthetic
root window; the failure case generates
an invalid unchecked core request to verify child-before-parent teardown.
The RandR case disables only the synthetic Xvfb CRTC, resizes its root to
1024x600 through XCB/RandR, verifies geometry-bound XShm/Damage/input
reconstruction keeps the same XCB descriptor, then verifies a new XDamage
notification is routed after the rebuild. The
`x11.desktop-resource-r4-read-boundary` case exercises the aggregate's real
XShm capture, XDamage snapshot/acknowledgement and XFixes cursor
refresh/image/ack path against the same ephemeral synthetic display. Borrowed
frame/cursor views are consumed synchronously before teardown. None inject
keyboard/mouse input or accesses a logged-in desktop.

Hosted Ubuntu installs `xvfb` and `xauth`; local absence means those
optional synthetic-display cases are NOT RUN, not PASS. When the concrete
Linux GSSAPI/R2 target and the one-XCB owner are both enabled, CMake also
builds noninstalled `rdp-server-linux-x11-authorized-input`. Its ordinary
`x11.input-r3-admission-route-denials-and-revocation` Xvfb CTest supplies no
admission lease and therefore cannot reach XTEST; it verifies missing
capability closes R3/R2 and the native owner. Positive input injection remains
outside ordinary CTest. The normal one-root owner command remains unchanged.

## Linux native X11 CLIPBOARD dependencies (R8)

When pkg-config finds `xcb`, Linux builds the noninstalled
`rdp-server-linux-x11-clipboard` target from the real
`src/x11/x11_clipboard_adapter.cpp`. Debian/Ubuntu provide the required
header/library through `libxcb1-dev`, already installed by hosted Linux CI.
The eight `clipboard.x11-*` CTests use a deterministic native-call seam and
need no `DISPLAY`, Xvfb, clipboard manager, RDP client or actual desktop
data. The INCR cases exercise large UTF-8, validated registered PNG,
PropertyDelete chunk progression, final zero-length completion, timeout,
generation/owner cancellation and requester destruction without a live X
server. Missing XCB development files mean this native target/test set is
**NOT RUN**, not PASS. The portable SDK and Windows/macOS builds do not gain
an XCB dependency. R5 still owns the sole XCB connection; the adapter borrows
it only while `X11DesktopResources` is valid. The owner's one-root command
is unchanged.

## Owner's required daily test from the latest GitHub main

Agents commit production code, its dedicated, registered behavior-named
CTest(s) and updated documentation **directly to `main`**. The owner does
not apply patches or merge branches. The following unchanged command must
configure, build and run the full applicable CTest suite in the **one**
persistent build root after fetching the latest `main`:

```sh
cd ~/rdp-server && git switch main && git pull --ff-only origin main && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON && cmake --build build --config Debug --parallel 2 && ctest --test-dir build -C Debug --output-on-failure
```

Run in the appropriate shell/toolchain environment on Linux/X11, Windows
MSYS2 CLANG64 (Clang 23) and macOS 27. Check `git rev-parse HEAD`
when comparing results and inspect CMake's effective compiler, because
a reused build cache does not select a new compiler automatically. Tests
requiring live desktop/input/clipboard, credentials or service activation
must be separately opt-in: the normal full CTest cannot require them.
Agents own build/test repairs via new direct-to-main commits; the owner
only reports the output of the command.

## Linux/macOS (CMake 3.22+, C++23 compiler, OpenSSL)

```sh
# If already cloned, skip clone and reuse the checkout.
git clone https://github.com/k1moradi/RDP-server.git "$HOME/rdp-server"
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

For Release, **reconfigure the same root** with
`-DCMAKE_BUILD_TYPE=Release` on single-config generators, understanding
it replaces prior configuration. Multi-config generators use
`--config Debug`/`--config Release` inside the same root.

## R6 Windows session-state linkage (2026-10-15; CI pending)

The noninstalled `rdp-server-windows-desktop` target now links
`wtsapi32` for read-only `WTSQuerySessionInformationW` session-state
observation, in addition to its existing `user32`, `d3d11` and
`dxgi` dependencies. The portable protocol SDK, Linux and macOS do
not gain WTS headers or libraries. This must compile under both hosted
Windows/MSVC and the owner's MSYS2 CLANG64/Clang 23; those toolchains
remain separate evidence gates.

## R6 native DXGI metadata linkage (2026-10-15; CI pending)

The noninstalled Windows-only `rdp-server-windows-desktop` adapter
explicitly links the Windows SDK `d3d11` and `dxgi` import libraries
alongside `user32`. This does not add native SDK dependencies to the
portable RDP protocol archive, Linux or macOS targets. Hosted
Windows/MSVC build and owner MSYS2 CLANG64 Clang23 are independent
verification gates; no ordinary CTest opens a live desktop.

## R6 Win32 cursor metadata linkage (2026-10-16; exact-SHA hosted PASS)

The same noninstalled `rdp-server-windows-desktop` target now compiles
`windows_cursor_snapshot.cpp` and links `gdi32` in addition to its
existing `user32`, D3D11, DXGI and WTS dependencies. `GetCursorInfo`
and `GetIconInfo` remain User32 calls; `GetObjectW`/`DeleteObject`
for the temporary cursor bitmaps require GDI32. No Windows cursor headers
or import libraries enter the installed portable protocol SDK. Hosted
Windows/MSVC and owner MSYS2 CLANG64/Clang23 remain independent compile
gates. Ordinary CTest uses synthetic callbacks and never reads a live cursor.
Implementation `0ee521f2802bb2f2fd3fd6fa1ebfb834f4d47287` compiled this
native target and passed **283/283** Windows/MSVC CTests in both Debug and
Release in Actions 38871393796. Owner MSYS2 CLANG64/Clang23 remains NOT RUN.

## Windows (PowerShell, MSVC and OpenSSL)

```powershell
$projectRoot = Join-Path $HOME "rdp-server"
$buildRoot = Join-Path $projectRoot "build"
cmake -S $projectRoot -B $buildRoot -DBUILD_TESTING=ON
cmake --build $buildRoot --config Debug --parallel 2
ctest --test-dir $buildRoot -C Debug --output-on-failure
```

Use C++23 standard mode without GNU extensions; GCC/Clang
`-Wall -Wextra -Wpedantic -Werror`, MSVC `/W4`.
Keep portable first-party code and OpenSSL separately from OS adapters.
Never compile/link xrdp, patched chansrv, VNC or another RDP daemon as
part of the active server. The current output is a protocol **library**,
not an independently usable RDP listener. Investigate build failures;
do not hide warnings, skip assertions or create a second build root.
Every implementation commit updates existing documentation/TODO and
runs [testing](testing_standards.md) gates.

## Verified build convention (2026-10-14)

At `3196a764ffbe24482ad131ad6949f1c2c23d44d9`, the checkout-local
single-build-root CMake configuration, build and CTest succeeded on all
three CI systems in [run 38535115706](https://github.com/k1moradi/RDP-server/actions/runs/38535115706).
This verifies CI checkout-local layout; it does **not** attest to the
existence of a persistent `~/rdp-server/build/` on the owner's machine
or to a production RDP daemon.

## Additional local-home-path enforcement (2026-10-14)

At `e1843b07c8772588f29e45a9b8e328e51c59e2ff`, the CMake
configure now **also refuses ordinary local checkouts outside
`~/rdp-server`**. The existing single `build/` root check applies
in both local and CI configurations. GitHub Actions
[run 38535723210](https://github.com/k1moradi/RDP-server/actions/runs/38535723210)
passed Linux, macOS and Windows with the explicit hosted-CI workspace
exception. No claim is made about directly executing a build on the
owner's local machine.

## Automated compilation, tests and artifact delivery (2026-10-14)

The existing `.github/workflows/ci.yml` owns one unified pipeline for
`main` pushes, pull requests, manual dispatches and protocol release
tags. Each Linux/macOS/Windows runner uses only its checkout-local
`build/` root, compiles/tests Debug, reconfigures **the same root**
for Release, compiles/tests again, and stages an SDK install in
`build/stage`. The downstream consumer uses `build/consumer` and
loads the installed `RDPServer::protocol` CMake export. CPack generates
a ZIP in `build/`, SHA-256 checksums, and uploads both to the CI run.

For an ordinary local dry run, reuse **only** `~/rdp-server/build/`:

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Release --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Release --output-on-failure
cmake --install "$HOME/rdp-server/build" --config Release --prefix "$HOME/rdp-server/build/stage"
cmake -S "$HOME/rdp-server/tests/consumer" -B "$HOME/rdp-server/build/consumer" -DCMAKE_PREFIX_PATH="$HOME/rdp-server/build/stage" -DCMAKE_BUILD_TYPE=Release
cmake --build "$HOME/rdp-server/build/consumer" --config Release --parallel 2
ctest --test-dir "$HOME/rdp-server/build/consumer" -C Release --output-on-failure
cmake --build "$HOME/rdp-server/build" --config Release --target package
```

Auto-publishing on `protocol-vX.Y.Z` tags is **prerelease delivery of
a development static library**, with no service activation or runtime
installation. The tag must match `PROJECT_VERSION` and point to a
commit reachable from `main`; tests on all 3 OSes and the documentation
gate must pass first. Do not describe this as RDP-server deployment
until a real authenticated server and OS adapters have been accepted.

## Verified SDK packaging on CI (2026-10-14)

The unified build/test/staged-install/downstream-consumer/CPack steps
passed in [Actions run 38543429777](https://github.com/k1moradi/RDP-server/actions/runs/38543429777)
for exact commit `1aa025960288d40f476e85c5a9c5f97b06bebf20`
on Linux, macOS and Windows. All runner output remained in the
runner's checkout-local `build/`; three distinct SDK ZIP artifacts
and SHA-256 manifests uploaded. The tag-triggered GitHub prerelease
job was SKIPPED (no tag). Direct local `~/rdp-server/build/` testing
and production server installation are NOT RUN.

## R10 runtime offline configuration syntax check (2026-10-15)

The R10 offline increment adds a native `rdp-server`
executable in the existing sole `build/` root. `rdp-server --help`
and `rdp-server --version` are informational. Attempting to start the
service fails with exit 2. `rdp-server --check-config FILE` performs
**offline syntax-only** validation (exit 0 for accepted syntax, exit
3 for invalid configuration). Accepted syntax does NOT verify real
certificate contents or OS authorization, and does not activate a
listener or server. The 25 `runtime.*` CTests execute without live
credentials, desktop access or socket binds. The SDK install/export
and CPack ZIP must remain protocol-only. Full project CI and local
same-main checkout validation remain NOT RUN at authoring.

## R10 offline POSIX configuration-file policy (2026-10-15)

The existing `rdp-server --check-config FILE` remains a syntax-only
diagnostic that never opens a listener. On POSIX platforms the config
file must be a regular file, not a final-component symlink, FIFO or
directory, and it cannot be group/world writable. A privately owned
file can be prepared with `chmod 600 /path/to/config`. Normal CTests
use generated synthetic files under the existing `build/runtime-fixtures`
directory. Windows currently validates syntax without native ACL/
reparse-point acceptance; do not use these checks as a substitute for
TLS certificate/private-key provisioning or OS authorization.
Five extra `runtime.*` CTests run only on POSIX and exercise the
actual runtime executable. The owner's established one-line
configure/build/CTest command is unchanged.

## R10 Windows native offline configuration handle (2026-10-15)

Windows `rdp-server --check-config FILE` accepts only drive-absolute
paths to disk-backed regular files without a final reparse point.
Four additional Windows-only `runtime.*` CTests use existing
`build/runtime-fixtures` data without accessing real credentials.
The owner's existing one-line CMake/CTest workflow is unchanged.
DACL and TLS private-key file permissions are NOT yet verified;
`--check-config` does not activate a service.

## R10 Windows offline config file DACL fixture gate (2026-10-15)

On Windows, `rdp-server --check-config` additionally inspects the
opened HANDLE's DACL for broad write/delete/permission-changing
grants. All Windows synthetic config fixtures in normal CTest are
given a private DACL using standard `whoami.exe` and `icacls.exe`,
then dedicated negative cases grant Everyone, Authenticated Users
or BUILTIN Users modify access and require exit 3. These commands
run only against files generated under `build/runtime-fixtures/`,
never a real credential or system file. The owner's normal CMake/
CTest one-liner is unchanged. No complete effective-access, TLS
private-key permissions or OS-admission claim is implied.

## R10 offline TLS-file metadata preflight (2026-10-15)

Use `rdp-server --check-config FILE` to validate syntax without
looking up TLS files. Use `rdp-server --check-tls-files FILE` to
add an offline metadata-only check of the configured actual cert/key
file paths. Accepted certificate files must be regular, nonempty,
at most 1 MiB, and not group/world writable on POSIX. Private keys
must be regular, nonempty, at most 256 KiB and owner-private
(`chmod 600`) on POSIX; the key owner must match the running eUID.
Windows checks non-reparse HANDLE identity and restricts key read
grants to owner/SYSTEM/Administrators. The cert and key may not
refer to the same underlying file (including via hard links).
A successful preflight does **not** validate X.509, PEM key
contents, private-key matching, expiry or service authorization,
and cannot start the server. Dedicated `runtime.*tls-files*`
CTests use synthetic content in `build/runtime-fixtures`.

## R10 POSIX TLS parent-path symlink gate (2026-10-15)

The separate `rdp-server --check-tls-files FILE` command checks
credential **metadata only**; syntax-only `--check-config` is
unchanged. On Linux/macOS, TLS files can reside in real nested
directories but none of their parent components may be symlinks.
The regular-file, size, owner, private-key mode and hardlink-alias
checks still apply. Three POSIX-only CTests generate safe synthetic
files under `build/runtime-fixtures`, including two parent-symlink
denials. The unchanged owner configure/build/CTest one-liner runs
these without genuine PEM data or a listener. Windows CLANG64
and real TLS contents remain separately unverified.

## R10 offline PEM credential consistency check (2026-10-15)

`rdp-server --check-tls-credentials FILE` runs the existing config
syntax and TLS-file metadata checks, then parses the already-open
certificate and private key as PEM and requires the key to match the
certificate. It never prompts for a password; encrypted private keys
are rejected. A passing result does not establish certificate trust,
hostname, chain, revocation, user authentication or permission to start the
RDP service. The certificate must be currently valid, match the private key,
and be acceptable to OpenSSL for TLS server use. Ordinary CTests use fixed
test-only EC material under `build/runtime-fixtures`; no real
credential is installed or read.

## Opt-in R9 Linux/Clang libFuzzer build

Normal builds leave `RDP_SERVER_BUILD_FUZZERS=OFF`. The Linux
sanitizer CI may set it ON while reusing that job's sole `build/`.
It requires Linux/Clang/CTest; the fuzzer target links
`-fsanitize=fuzzer,address,undefined`. Corpus and crash outputs
remain in `build/fuzz-corpus-mcs-cliprdr` and
`build/fuzz-artifacts-mcs-cliprdr`. Do not create `build-fuzz`
or alter the owner's unchanged configure/build/CTest command.


## R7 ScreenCaptureKit stream lifecycle and CoreVideo handoff (2026-10-16)

On Apple, the existing `rdp-server-macos-capture` target now enables Objective-C++ only inside the `APPLE` block and compiles `screen_capture_stream.mm` with ARC. The target links `ScreenCaptureKit`, `Foundation`, `CoreMedia`, `CoreVideo`, `CoreGraphics`, and `CoreFoundation`; none of these dependencies are added to `rdp-server-protocol`, Linux, or Windows. The existing CMake command remains valid and does not require Xcode project generation or a second build tree.

Ordinary CTests do not invoke the native ScreenCaptureKit backend. They use the production C++ lifecycle owner with an injected backend and synthetic CoreVideo buffers, so a normal test run neither starts live screen capture nor requests TCC permission. Compiling/linking the Objective-C++ source on macOS is evidence that the SDK bridge builds; it is not evidence that a live screen was captured.


## R4 static x264 encoder dependency (2026-10-16)

The normal owner configure/build/CTest command is unchanged. R4 builds the
pinned sources under `third_party/x264` as a static `rdp-server-x264`
library and links it only into noninstalled `rdp-server-graphics`. No
network fetch, system x264 installation, FFmpeg, NASM, OpenCL or second build
tree is required. The portable installed `RDPServer::protocol` SDK remains
x264-free.

The first integration deliberately uses x264's portable C implementation with
one encoder thread and no assembly optimizations. This is a correctness-first
cross-platform build contract; SIMD/thread tuning requires later R4/R9
measurement and must not silently change frame ordering or ownership.


## R7 generation-safe macOS cursor snapshot boundary (2026-10-16)

The Apple-only `rdp-server-macos-capture` target now also compiles `mac_cursor_snapshot.mm` with ARC and links AppKit in addition to the existing ScreenCaptureKit/CoreGraphics/CoreVideo stack. AppKit is not linked into the portable protocol SDK or non-Apple builds. Deprecated system-wide cursor introspection calls are locally warning-suppressed only in this translation unit; the target otherwise retains `-Wall -Wextra -Wpedantic -Werror`.

The existing `test_macos_capture_pixel_buffer` executable gains three synthetic cursor cases on every OS. Non-Apple builds compile only `mac_cursor_snapshot.cpp`; Apple additionally compile/links the real AppKit bridge through `rdp-server-macos-capture`, but ordinary CTest never invokes `queryNativeMacCursorSnapshot`. No TCC prompt, live cursor read or input event is part of the standard test command.


## R7 generation-pinned macOS input controller (2026-10-16)

The Apple-only `rdp-server-macos-capture` target also compiles `mac_input_controller.mm` and links ApplicationServices for the non-prompting Accessibility trust query; CoreGraphics already supplies Quartz event construction/posting. The native posting callback remains private to that translation unit and is not runtime-wired. No extra framework dependency reaches the installed portable protocol SDK or non-Apple builds.

`test_macos_input_controller` is registered on every OS with three ordinary cases: `macos.input-controller-lifecycle`, `macos.input-controller-validation-denials`, and `macos.input-controller-revocation-cleanup`. Non-Apple builds compile the portable controller plus synthetic geometry sources directly. Apple links the production macOS target, which compile/links the real Quartz/ApplicationServices bridge, but the tests inject their own callback and never query Accessibility or post native events.


## R7 synchronous macOS desktop session/permission guard (2026-10-16)

The Apple-only `rdp-server-macos-capture` target now also compiles `mac_desktop_session_guard.cpp`. Its native path uses CoreGraphics/CoreFoundation already linked by the R7 target and the existing non-prompting Screen Recording/Accessibility probes; no new framework reaches the portable protocol SDK.

`test_macos_desktop_session_guard` is registered on every OS with `macos.desktop-session-lifecycle`, `macos.desktop-session-validation-denials`, and `macos.desktop-session-revocation-reentry`. Non-Apple builds compile the portable guard plus synthetic geometry directly. Apple links the production R7 target, but ordinary CTest injects synthetic session/permission callbacks and never calls `CGSessionCopyCurrentDictionary`, queries real TCC/Accessibility state, starts capture, or posts input.


## R7 NSWorkspace session-change observer linkage (2026-10-16)

The Apple-only `rdp-server-macos-capture` target compiles
`native_session_change_watch.cpp` plus ARC Objective-C++
`native_session_change_watch.mm`. It reuses the target's existing AppKit and
Foundation linkage; no new native framework enters the installed portable
protocol SDK, Linux or Windows builds. Non-Apple
`test_macos_desktop_session_guard` compiles the portable watch source directly.

Ordinary CTest uses an injected registration backend and the production atomic
revision recorder; it never creates `NSWorkspace` observers. Native
`startNative()` is explicit and fails closed unless called from an
already-running AppKit main event-loop context. Hosted Apple compilation proves
SDK/API linkage only; it does not prove real fast-user-switch notifications
were delivered. Owner macOS 27 remains the separate delivery/desktop acceptance
gate.


## R7 portable framebuffer bridge build wiring (2026-10-16)

`capture_framebuffer_view.cpp` is compiled into the Apple-only
`rdp-server-macos-capture` target. On non-Apple hosts the standard synthetic
macOS fixture compiles that portable source directly beside
`capture_pixel_layout.cpp`, so stride/storage contract regressions are caught
without CoreVideo or ScreenCaptureKit headers.

The bridge is header-only with respect to R4 ownership: it consumes
`core/framebuffer_view.h` but does not link `rdp-server-graphics`, x264 or
any protocol transport target. Apple `test_macos_capture_stream` continues to
link the private macOS capture target only for SDK/lifecycle compile coverage;
the public native ScreenCaptureKit factory remains absent.


## R4 sanitizer compiler coverage for vendored x264 (2026-10-16)

Ordinary builds remain unchanged. In the existing Linux sanitizer CI job only,
CMake selects `clang` for C as well as `clang++` for C++, applying the same
ASan/UBSan compile flags to both languages. The repository's C translation
units are exclusively the pinned `third_party/x264` sources, so this directly
instruments the real codec while the existing R4 C++ converter/producer and
test executables are instrumented through the C++ flags. Link sanitizer flags
remain on the test executables. No system x264, alternate build directory or
new dependency is introduced.
