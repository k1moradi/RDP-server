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

## Build the standalone C++23 protocol foundation

The library has **no xrdp source download, patched chansrv, VNC/RFB daemon or
packaged xrdp services**. A C++23 compiler, CMake 3.22+ and OpenSSL development
libraries are required.

```bash
git clone https://github.com/k1moradi/RDP-server.git "$HOME/rdp-server" # skip if already cloned
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
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

The first-party project is GPL-3.0-or-later. All reused third-party code
must preserve its original notices and compatible licensing; see
[third-party attributions](docs/THIRD_PARTY.md). The project
traces historical upstream-derived work transparently; code origin is not
the same thing as a runtime dependency.

## Branch policy

No new branches may be created by assistants or automated agents unless the
repository owner explicitly requests them. Develop on the existing
`main` branch until otherwise instructed.

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
