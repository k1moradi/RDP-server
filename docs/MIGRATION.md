# Migration provenance and scope

## New project home

[`k1moradi/RDP-server`](https://github.com/k1moradi/RDP-server)
is the standalone, open-source C++23 RDP server protocol project.

**Motto:** RDP protocol first. Fast native C++23 implementation. No
workarounds when a standards-compliant RDP mechanism already solves the problem.

## Transfer completed

The following **125 first-party C++ `.cpp`/`.h` files** were copied from
historical `k1moradi/xrdp-console`, frozen at commit
`1a8b83f07165783d62ce5f6657d4e1670ce62ff4`:

- `src/server`: 50 files, transport/security/clipboard/adapters
- `src/rdp`: 38 files, native graphics algorithms
- `src/core`: 19 files, geometry, scheduling and image state
- `src/clipboard`: 4 files, clipboard wire formats and validation
- `src/x11`: 14 files, candidate OS-specific Linux/X11 adapters

Source namespaces were migrated from `xrdp_console` to `rdp_server`.
The original GPL-3.0 license and creator attribution were retained.
Microsoft protocol fixtures and focused C++23 tests were imported.

The published CMake archive currently compiles **14 portable C++23 translation
units**. The remaining files are staged source under architectural review:
their presence does **not** mean they are linked into a functional server.

Two direct dependencies on upstream C have been replaced in the new home:
a native bounded RFC 4648 Base64 implementation replaces the old imported
`base64.c`, and the CLIPRDR coordinator no longer imports the old
`ms-rdpeclip.h`. This does not invalidate upstream author credit for
historical research.

## Deliberately not migrated

The old source tree had patched xrdp 0.10.6.1, chansrv and a patch series,
Linux systemd deployment scripts, RFB/VNC benchmarks, private host-test
harnesses, and binary fixture archives. These are **not** the new product's
dependencies, server implementation or release artifacts. They remain at
[`k1moradi/xrdp-console`](https://github.com/k1moradi/xrdp-console)
for historical traceability and to resolve outstanding experiments.

The Git history, pull requests, historical development branches and issues of
the old project have not been mechanically moved: the new repository was
created independently with its own `main` history and selected first-party
source migration. No new development branches were created.

## Outstanding implementation blockers

No tested production RDP daemon exists yet. Implement and accept a complete
server handshake, authenticated session and post-auth channel lifecycle;
graphics and desktop capture/input adapters across OSes; bidirectional
CLIPRDR; and client acceptance before describing RDP-server as usable.
See `docs/ROADMAP.md`. Do not hide missing functionality behind an
xrdp-dependent fallback.
