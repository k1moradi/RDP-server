# Migration provenance and scope

## Full-project recovery pending

**The complete former `xrdp-console` repository was NOT moved.** The
original GitHub repository has been deleted; the new repository has only
the 125 selectively migrated C++23 files and limited protocol tests.

If the original `~/xrdp-console` Git checkout still exists on the dedicated
development PC, the checked-in [full-history importer](../scripts/import-full-project.sh)
copies **all files tracked in its historical `main`**, preserves the current
standalone C++23 build, and creates a single two-parent commit joining both
repositories' real Git histories. It pushes to **the existing `main`**:
no new branches and no force push.

```bash
cd ~
git clone https://github.com/k1moradi/RDP-server.git
cd RDP-server
bash scripts/import-full-project.sh /home/keivan/xrdp-console
```

If `~/RDP-server` already exists, use `git -C ~/RDP-server pull --ff-only`
instead of cloning, then execute the importer there. It requires a clean
current new-repository checkout. It never activates a daemon, touches the
clipboard, makes backups, or alters the old working tree.

The importer verifies the original tracked-file inventory and requires that
the remote `main` has not moved since the local checkout. Its merge commit
preserves both parents. It imports the old project’s Linux runtime, patched
xrdp files and test infrastructure **as archival migration source**, while
keeping the active default CMake build independent of xrdp and VNC. Such
files are present but are not part of the new active C++23 protocol archive.

If the old checkout has been lost, GitHub permits restoration of eligible
deleted repositories within 90 days: Settings → Repositories → Deleted
repositories → Restore. Only the account owner can perform that web action.
Once restored, the original source and history can be imported. The
source is not currently recoverable by this assistant's GitHub connector
while the deleted repository returns 404.

**This is not yet confirmation that the full import has executed.** The
original local checkout remains outside the assistant's tool access.


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
