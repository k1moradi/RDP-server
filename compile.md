# Compile standards — one persistent and reusable build directory

**Mandatory:** Follow [AGENTS.md](AGENTS.md), [VISION.md](VISION.md),
[testing_standards.md](testing_standards.md) and the living
[roadmap/TODO](docs/ROADMAP.md). New verified compilation lessons
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
CMake enforces `CMAKE_BINARY_DIR == <checkout>/build`.

GitHub-hosted CI cannot persist the owner's home checkout across jobs,
so **each isolated job** uses exactly one ephemeral
`<checkout>/build` and does not commit its output.

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
