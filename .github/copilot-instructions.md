# Copilot instructions — RDP-server

Read the **canonical mandatory [AGENTS.md](../AGENTS.md)** at the start
of every prompt, plus [VISION.md](../VISION.md),
[docs/ROADMAP.md](../docs/ROADMAP.md), the four mandatory
[coding](../coding_standards.md),
[testing](../testing_standards.md),
[compilation](../compile.md) and
[benchmark](../benchmark.md) standards, and
[CODEX_VALIDATION.md](../CODEX_VALIDATION.md).

Existing `main` only unless the owner explicitly authorizes a branch.
Reuse exactly one local **`~/rdp-server/build/`**.
Keep native RDP C++23 code modular, one controller per state machine,
and tests in reusable behavior-named suites. Update canonical docs
and the live TODO in the same commit after every implementation.
No xrdp/VNC runtime, silent test weakening, or unapproved deployment.
