# Compile standards — one persistent and reusable build directory

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

## Linux native XFixes cursor development dependencies (R5)

When `pkg-config` discovers both `xcb` and `xcb-xfixes`, the
Linux build compiles `rdp-server-linux-xfixes-cursor` from actual
`x11_cursor_tracker.cpp` and `cursor_image_conversion.cpp`.
On Debian/Ubuntu, install `libxcb1-dev` and
`libxcb-xfixes0-dev`; the existing GitHub Actions Linux job
provisions both. The new native-only
`x11.cursor-native-connection-denials-and-cancellation` CTest is
registered only when this target exists. Absence of the development
headers means native source/test NOT RUN, not PASS. No running X server,
live desktop, or credentials are needed for ordinary tests. The
owner's single `build/` command and portable SDK remain unchanged.

## Linux-only native XDamage dependencies (R5)

The first-party `rdp-server-linux-xdamage` target is built when
`pkg-config` finds `xcb` and `xcb-damage`. Debian/Ubuntu
development packages: `libxcb1-dev` and `libxcb-damage0-dev`.
Linux hosted CI installs them. The target compiles the actual
`src/x11/x11_damage_tracker.cpp` plus the existing bounded
`src/core/damage_region.cpp`, with strict C++23 warnings. Its
dedicated `x11.damage-native-connection-denials-and-cancellation`
CTest requires no X server, logged-in session or live capture.
If headers/libs are unavailable, this native target/test are not
built and must be marked NOT RUN (not PASS). The owner's existing
one-root configure/build/CTest command is unchanged, and XCB
remains excluded from installed portable protocol headers.

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

## R6 native DXGI metadata linkage (2026-10-15; CI pending)

The noninstalled Windows-only `rdp-server-windows-desktop` adapter
explicitly links the Windows SDK `d3d11` and `dxgi` import libraries
alongside `user32`. This does not add native SDK dependencies to the
portable RDP protocol archive, Linux or macOS targets. Hosted
Windows/MSVC build and owner MSYS2 CLANG64 Clang23 are independent
verification gates; no ordinary CTest opens a live desktop.

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
