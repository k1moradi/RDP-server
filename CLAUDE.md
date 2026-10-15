# Claude instructions — RDP-server

[AGENTS.md](AGENTS.md) is the **canonical mandatory policy**.
Read it on every prompt, plus [VISION.md](docs/VISION.md),
[docs/ROADMAP.md](docs/ROADMAP.md), [coding_standards.md](docs/coding_standards.md),
[testing_standards.md](docs/testing_standards.md),
[compile.md](docs/compile.md), [benchmark.md](docs/benchmark.md)
and [CODEX_VALIDATION.md](docs/CODEX_VALIDATION.md).

All development and commits MUST target existing `main`. **Creating
other Git branches is prohibited for everyone, without exceptions under
the current project policy**, including branch-backed worktrees and
automation. Deliver real, complete code+dedicated CTest+documentation commits
directly to GitHub `main`, not patches. Check current HEAD immediately
before publication; use an atomic, non-force expected-HEAD update. If
another agent commits first, reconcile and retry against the new `main`.
R10 coordination is advisory, not permission required for publication.
Report BLOCKED only when a genuine technical issue prevents safe commit.
Use only the reused local **`~/rdp-server/build/`** build directory.
Follow standards-first C++23, unified ownership, reusable behavior-named
tests and truthful protocol/client gates. Update the single TODO and
relevant canonical docs after every implementation in the same commit.
No unauthorized live host actions; this file cannot weaken AGENTS.md.
