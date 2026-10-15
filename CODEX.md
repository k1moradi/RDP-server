# CODEX.md — RDP-server agent contract

**Canonical mandatory policy: [AGENTS.md](AGENTS.md).** Read it on every
prompt along with [VISION.md](docs/VISION.md), the living TODO in
[docs/ROADMAP.md](docs/ROADMAP.md), [coding_standards.md](docs/coding_standards.md),
[testing_standards.md](docs/testing_standards.md), [compile.md](docs/compile.md),
[benchmark.md](docs/benchmark.md) and [CODEX_VALIDATION.md](docs/CODEX_VALIDATION.md).
One reused local build: `~/rdp-server/build/`. Use consolidated semantic
CTest modules. Each implementation must update the same TODO and pertinent
canonical docs **in the same commit**, with accurate tests and limitations.


**MAIN ONLY — creating any Git branch is prohibited, without exceptions
under the current project policy.** All development, tests, documentation
and implementation commits target the existing `main` branch. Do not use
`git switch -c`, `git branch <name>`, `git checkout -b`,
branch-backed worktrees, GitHub branch-create endpoints or branch-creating
automation. Do not create development commits on detached HEAD. Ten agents
must implement **and commit completed code+dedicated CTests+docs directly
to GitHub `main`**, not merely prepare patches or wait for R10 approval.
For concurrent updates, fetch the latest `main`, commit atomically on
its current HEAD, and publish via non-force fast-forward with an expected
HEAD check; if HEAD changed, reconcile and retry on the newer `main`.
Report BLOCKED only for real technical conflicts or access failures.
The owner's pull/build/full-CTest one-liner must test every applicable
registered test. See [AGENTS.md](AGENTS.md).

## Mission

> RDP protocol first. Fast native C++23 implementation. No workarounds when a
> standards-compliant RDP mechanism already solves the problem.

The aim is a standalone, cross-platform, open-source **C++23** RDP server,
not a patched xrdp runtime, VNC bridge or proprietary client shim. Do not
invent new transport, clipboard or graphics semantics if standard RDP
mechanisms exist. Preserve third-party attributions and GPL compliance.

## Correctness and deployment

- The source currently provides a protocol foundation only, not a complete
  installable server. Do not label tests or connection probes "RDP server
  acceptance" without external real-client authenticated desktop verification.
- No host activation, service restart, reboot, live user clipboard read,
  desktop takeover or human interaction without explicit authorization.
- Avoid default rollback backups or service activation script reintroduction.
- Run native C++23 compile, protocol unit tests, and cross-platform
  build checks when making protocol changes.
- Never add an xrdp, chansrv, VNC/RFB or patched upstream C runtime as a
  build dependency. OS-specific adapters are separate modules.
- Record the first failing wire-protocol boundary, keep output truthful,
  and fix code instead of hiding failing tests or forcing merges.
