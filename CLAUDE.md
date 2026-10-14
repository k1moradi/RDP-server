# Claude instructions — RDP-server

[AGENTS.md](AGENTS.md) is the **canonical mandatory policy**.
Read it on every prompt, plus [VISION.md](docs/VISION.md),
[docs/ROADMAP.md](docs/ROADMAP.md), [coding_standards.md](docs/coding_standards.md),
[testing_standards.md](docs/testing_standards.md),
[compile.md](docs/compile.md), [benchmark.md](docs/benchmark.md)
and [CODEX_VALIDATION.md](docs/CODEX_VALIDATION.md).

Work on existing `main` only absent explicit authorization.
Use only the reused local **`~/rdp-server/build/`** build directory.
Follow standards-first C++23, unified ownership, reusable behavior-named
tests and truthful protocol/client gates. Update the single TODO and
relevant canonical docs after every implementation in the same commit.
No unauthorized live host actions; this file cannot weaken AGENTS.md.
