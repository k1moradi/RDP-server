# Agent instructions — RDP-server

**Mandatory canonical policy:** [AGENTS.md](AGENTS.md). Read it on
**every prompt** with [VISION.md](docs/VISION.md),
[docs/ROADMAP.md](docs/ROADMAP.md), and all four standards:
[coding](docs/coding_standards.md), [testing](docs/testing_standards.md),
[compilation](docs/compile.md), [benchmarking](docs/benchmark.md).
See [CODEX_VALIDATION.md](docs/CODEX_VALIDATION.md) for validation.

All development and commits are on existing `main` only. **No Git branch
creation by anyone, including agents, tools and automation; no exceptions
under the current policy.** Commit finished increments (implementation, dedicated CTests and docs)
**directly to GitHub `main`**, not as patches or R10 handoffs. Use a
non-force expected-HEAD update; rebase the proposed changes onto current
`main` and retry if another agent publishes first. Only real technical
blockers justify stopping before publication.
Reuse **`~/rdp-server/build/`** for all local builds.
Prefer consolidated C++23 modules, semantic reusable CTests,
and minimal documentation fragmentation. Every implementation updates
its existing TODO and affected canonical docs in the same commit.
Do not claim a working server from passing library tests.
