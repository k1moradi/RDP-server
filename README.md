# RDP-server

> **Project status:** The maintained first-party C++23 protocol library
> is only a foundation, not a working standalone RDP server. The old
> `xrdp-console` repository was deleted and its complete source was
> not migrated. The legacy-source import scripts and guide have been
> retired; see [the living roadmap](docs/ROADMAP.md) for current work.


**Open-source C++23 implementation of the Remote Desktop Protocol (RDP) server.**

> **RDP protocol first. Fast native C++23 implementation. No workarounds when a standards-compliant RDP mechanism already solves the problem.**

## Mission

RDP-server aims to deliver a fast, secure, interoperable, **standalone,
platform-independent C++23 RDP server**, without requiring xrdp, a VNC/RFB
server, or an existing RDP daemon. Target Windows, macOS, Linux, BSD and other
operating systems through a portable protocol core and OS-specific adapters.

**Current status: under construction — not yet a functional standalone
RDP server.** This repository contains the migrated first-party C++23
protocol, clipboard, security, graphics, core and X11 adapter source. A
subset is compiled as a platform-independent static protocol archive;
additional imported algorithms are staged for review.

The implementation covers parts of X.224/TPKT, MCS/GCC, security
negotiation, CredSSP framing, CLIPRDR and graphics policy, but a complete
authenticated RDP listener, desktop backend, input, virtual channel
management, clipboard integration and interoperable end-to-end runtime are
still incomplete. No ready-to-install server is claimed here.

The former xrdp-console GitHub repository was deleted. Its historical
code is not a dependency of the maintained native C++23 protocol library.
No automated legacy-source import workflow is part of this repository.

## Desktop startup contract

The normal consumer application command is:

```text
rdp-server-desktop
```

with **no required arguments**. The intended product workflow is portable ZIP
→ extract → double-click → set Session Password → explicit Sharing ON → connect
over the LAN. Normal startup must not require a user-authored `server.conf`,
`--config`, TLS/licensing key files, Kerberos/keytab/PAM setup or native
UID/seat/display/listener policy files. `--config` remains an expert/legacy
override.

Portable persistent state belongs in OS per-user application-data/config
storage; Session Password is memory-only by default. On first launch, Username
may suggest the safely observed current local interactive account name when
available. That editable suggestion is convenience only and does not map the
remote credential to the OS account. Session Password always starts empty and
is never recovered or auto-filled from an OS login or credential store. R1 already supports an
endpoint-bound process-memory TLS identity for the no-file Linux HostControl
path. Starting the GUI may bootstrap local prerequisites but never starts a
listener, installs a service or changes firewall/Windows RDP/macOS system
configuration. The extracted ZIP may be read-only.

**Current limitation:** this is the required product/bootstrap contract, not an
end-to-end readiness claim. Automatic TLS preparation has landed, but the
no-argument GUI still needs the remaining R2/R3/R10 Session Password, native
owner-authority and licensing/runtime provisioning path before the workflow
above is a working RDP host. Earlier GUI Round 2 PASS evidence qualifies
presentation only.

## Build the standalone C++23 protocol foundation

The library has **no xrdp source download, patched chansrv, VNC/RFB daemon or
packaged xrdp services**. A C++23 compiler, CMake 3.22+ and OpenSSL development
libraries are required. Ordinary application builds also require Qt 6.4+
Widgets because the desktop GUI is enabled by default; a deliberate
protocol-only/headless build must set `RDP_SERVER_BUILD_DESKTOP_GUI=OFF`.

```bash
git clone https://github.com/k1moradi/RDP-server.git "$HOME/rdp-server" # skip if already cloned
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
  -DRDP_SERVER_BUILD_DESKTOP_GUI=OFF
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

The output is `rdp-server-protocol`, a **static library**, not an installable
remote desktop server. The source layout is deliberately separated:

- `src/server/transport` — X.224, TPKT, GCC, MCS and negotiation primitives.
- `src/server/security` — C++23 CredSSP/DER, TLS binding and identity policies.
- `src/server/clipboard` and `src/clipboard` — CLIPRDR transfer serialization,
  PNG and DIB payload validation.
- `src/core` and `src/rdp` — native graphics, geometry and frame/cache logic.
- `src/x11` — candidate **Linux/X11-specific platform adapter**, not a
  requirement for macOS, Windows or the portable protocol library.
- `tests` — regression tests and Microsoft RDP protocol example fixtures.

The original project contained many more Linux deployment scripts, binary
graphics fixtures, patched xrdp C files and experimental tests. They were
**not** blindly copied into this standalone C++23 repository. No new
development branches were created during migration.

## Required project documents and living TODO

**Every agent must read [AGENTS.md](AGENTS.md) on every prompt.**
[Project vision](docs/VISION.md) and the [live roadmap/TODO](docs/ROADMAP.md)
guide every change. The four mandatory canonical engineering documents
are [coding standards](docs/coding_standards.md),
[testing standards](docs/testing_standards.md),
[compilation](docs/compile.md), and [benchmarking](docs/benchmark.md).
See [validation evidence](docs/CODEX_VALIDATION.md). All new learned policies
belong in the relevant existing standard; don't fragment them.

Other agent-specific entry points — [CODEX.md](CODEX.md),
[CLAUDE.md](CLAUDE.md), [agent.md](agent.md), and
[GitHub Copilot instructions](.github/copilot-instructions.md) — all defer to
the canonical [AGENTS.md](AGENTS.md); none overrides it.

After every implementation, update the existing TODO and affected
documentation in the **same commit**. Maintain **one reused local
`~/rdp-server/build/`**; hosted CI has one ephemeral checkout-local
`build/` per job.

## Architectural rules

1. **Standards before workarounds.** Implement the documented RDP capability
   negotiation, protocol state machines and server channels; reject malformed
   traffic and unsupported mechanisms explicitly.
2. **Native C++23.** The server implementation and protocol code belong in
   maintained C++23 source. OpenSSL, native OS frameworks and standard
   system security APIs may be used as dependencies; an xrdp or VNC runtime
   must not be a dependency.
3. **Portable core, replaceable platform adapters.** Keep transport, RDP
   framing, authentication flow, graphics codecs, clipboard and input protocol
   independent of operating-system capture and input APIs.
4. **Secure by default.** Validate bounds and identities, require suitable
   authentication and encryption, and never advertise a debug probe as a
   production-ready listener.
5. **Measurable performance.** Minimize copies, allocations, latency and
   unnecessary encoding; test client compatibility and difficult network
   and clipboard conditions.
6. **Honest acceptance gates.** Passing unit or loopback tests does not mean
   a complete Microsoft/FreeRDP-compatible, usable desktop server.

## Protocol delivery plan

| Layer | Target | Current acceptance |
| --- | --- | --- |
| X.224 / TPKT / MCS / GCC | Fully interoperable session negotiation | Partial C++23 core only |
| TLS / NLA / CredSSP | Authenticated and identity-bound server sessions | Partial building blocks |
| Licensing, capabilities and share control | Standards-compliant post-auth session | Not complete |
| Graphics | Classic bitmap, RDPGFX and negotiated codecs | Reusable algorithms exist, not integrated server |
| Input | Keyboard, pointer and keyboard layout | Not integrated |
| Clipboard (CLIPRDR) | Unicode, PNG and DIB, including macOS screenshot to browser `File` | Wire-format/transfer work exists; acceptance not met |
| Other virtual channels | Lifecycle, dynamic channel routing, optional device services | Not complete |
| OS integration | Separate backends for Linux, Windows, macOS, others | Not complete |
| Packaging and release | Self-contained installs without xrdp/VNC | Not complete |

See [the architectural charter](docs/ARCHITECTURE.md) and
[living development roadmap](docs/ROADMAP.md).

## License and credits

The first-party project is [GPL-3.0-or-later](LICENSE). All reused third-party
code must preserve its original notices and compatible licensing; see
[NOTICE](NOTICE) and [third-party attributions](docs/THIRD_PARTY.md). The project
traces historical upstream-derived work transparently; code origin is not
the same thing as a runtime dependency.

## Branch policy — main only

**All project development and commits must occur on the existing `main`
branch. Creating any additional local or remote Git branch is prohibited**
for contributors, assistants, agents and automation, without exceptions
under the current policy. No feature, hotfix, release, temporary,
experimental or branch-backed worktree branches. **Each development
agent implements and publishes its finished code, dedicated CTests and
documentation directly to GitHub `main`**; patch-only delivery or
waiting for R10 publication approval is not the default. Parallel agents
use an atomic, non-force update against the expected current HEAD. If
another agent commits first, re-read/reconcile the changed files and
retry without overwriting anyone else's work. The owner pulls `main`
and runs the ordinary Debug build and full CTest on each platform.
Same-SHA convergence evidence requires recording each tested SHA;
ordinary agent commits are not held pending owner tests. Release
tags may point to verified commits on `main`; tags are not branches.
See [AGENTS.md](AGENTS.md) and the [roadmap](docs/ROADMAP.md).

## Automated compilation, testing and protocol SDK delivery

Every push to `main`, pull request, or manual GitHub Actions dispatch
compiles and runs the consolidated C++23 protocol CTests on
**Linux/GCC, macOS/Clang and Windows/MSVC**. Each runner uses a
single checkout-local `build/` directory: Debug builds/tests,
reconfigured Release builds/tests, then a staged install and a
separate **downstream CMake consumer smoke test** nested under
`build/consumer/`. The CI produces an OS-specific ZIP containing
the static protocol library, headers, CMake package exports,
license/attribution files and SHA-256 checksums. Packages are attached
to the workflow as GitHub Actions artifacts (30-day retention).

## SERVER-TEST preview delivery

Main-branch CI also creates a **separate** startup-disabled SERVER-TEST artifact
family from the actual `rdp-server` executable after the full Release CTest:
`rdp-server-test-<version>-<platform>-<architecture>-<short-sha>.zip`.
These ZIPs are never copies or renames of `rdp-server-protocol-*.zip`.

Each SERVER-TEST preview records the exact Git SHA, OS/architecture/ABI,
compiler identity and Release configuration; resolved runtime dependencies;
per-file and outer SHA-256 digests; LICENSE/NOTICE/third-party attribution; a
loopback-only non-secret sample config; and explicit install/start/stop/uninstall
instructions. CI extracts the archive into an ephemeral directory, validates
the binary ABI, `--version`, `--help`, config syntax, refusal of unconfigured
`serve`, no installation-time listener, idempotent install/uninstall,
absence of autostart and a credential-marker scan. A final R9 job downloads all
three platform previews and re-verifies their exact-SHA statuses and outer
digests.

Linux additionally carries R5's disabled user-service template without
installing or enabling it. Windows (R6) carries a per-user PowerShell
install/verify/start/status/stop/uninstall lifecycle plus the resolved
non-system runtime DLL closure beside `rdp-server.exe`; its Start action is
still fail-closed and never launches the server. macOS (R7) retains its
startup-disabled per-user LaunchAgent review contract. See
[Windows SERVER-TEST bundle](docs/WINDOWS_TEST_BUNDLE.md) for the R6 package
boundary. R7's separate macOS **protocol-only** test bundle remains exactly
that and is not a server.

A manual dispatch may opt in with `server_test_preview=true`; ordinary
main pushes build the same disabled previews for assurance. There is **no
SERVER-TEST release tag or GitHub release publisher yet**. A RUNNABLE human-test
prerelease remains blocked on R10 secure startup, exact-head green CI and
explicit owner acceptance. Hosted preview CI is not an M1 owner-native receipt
and never substitutes for the three-client M2 human acceptance matrix.


**Automatic deployment of available artifacts:** pushing an authorized
version tag `protocol-v0.1.0` (matching `project(... VERSION 0.1.0)`
and pointing to a commit already on `main`) runs all checks and,
only if all succeed, publishes the three tested ZIPs and their
checksums to a **GitHub prerelease**. A version bump and matching
`protocol-vX.Y.Z` tag are required for subsequent publications.
This does **not** install, start, deploy or expose an RDP server,
which is still unimplemented. No GitHub repository branch is created.

Downstream CMake users can unpack the appropriate ZIP and configure
with `-DCMAKE_PREFIX_PATH=<unpacked-package-root>`, then use
`find_package(RDPServerProtocol CONFIG REQUIRED)` and link
`RDPServer::protocol`; OpenSSL development libraries are required.
The package is a developer SDK, not a desktop service.
