# Agent instructions — RDP-server

**Mandatory canonical policy:** [AGENTS.md](AGENTS.md). Read it on
**every prompt** with [VISION.md](VISION.md),
[docs/ROADMAP.md](docs/ROADMAP.md), and all four standards:
[coding](coding_standards.md), [testing](testing_standards.md),
[compilation](compile.md), [benchmarking](benchmark.md).
See [CODEX_VALIDATION.md](CODEX_VALIDATION.md) for validation.

Only existing `main`; no branch creation without explicit owner request.
Reuse **`~/rdp-server/build/`** for all local builds.
Prefer consolidated C++23 modules, semantic reusable CTests,
and minimal documentation fragmentation. Every implementation updates
its existing TODO and affected canonical docs in the same commit.
Do not claim a working server from passing library tests.
