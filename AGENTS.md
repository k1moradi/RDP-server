# AGENTS.md — canonical mandatory RDP-server policy

This document governs **every prompt** for ChatGPT, Codex, Claude, Copilot
and other coding agents. Read it before analysis, edits, tests or reviews.
Other agent instructions may add requirements but cannot weaken this policy.
Never import policy from an unrelated project.

> RDP protocol first. Fast native C++23 implementation. No workarounds when a standards-compliant RDP mechanism already solves the problem.

## Required context and architecture

Read current `main` versions of `AGENTS.md`, `docs/VISION.md`,
`docs/ROADMAP.md`, `docs/coding_standards.md`, `docs/testing_standards.md`,
`docs/compile.md`, `docs/benchmark.md` and `docs/CODEX_VALIDATION.md`
**at the beginning of each prompt**. Read affected source and existing tests.
Consult Microsoft's normative RDP specifications before wire design;
keep C++23 protocol independent of xrdp, VNC and OS-specific adapters.
The existing static library is **not** a functional independent RDP server.

`docs/VISION.md` owns product objectives. **`docs/ROADMAP.md` owns the sole
current milestone/TODO list**; re-read the relevant item before work and
update it when evidence, scope or blockers change. The four mandatory standards in `docs/` own coding, testing, build
and benchmark rules, respectively.
New project lessons belong in the **relevant existing standards document**,
not another competing policy, TODO, test or experiment report.
Keep `README.md`, `AGENTS.md`, `CODEX.md`, `agent.md` and `CLAUDE.md`
at the repository root for discovery. Keep other Markdown reference
material under `docs/` and update its links when it moves.
`README.md` provides public orientation and `docs/CODEX_VALIDATION.md`
records validation results; both link to the canonical details.

**After every implementation prompt**, update the affected existing
documentation and live TODO in the **same commit** as code, tests or CI,
with exact SHA, commands, PASS/FAIL/BLOCKED/NOT RUN and next gate. Do not
mark a task complete from unverified or synthetic evidence.

## One persistent local build root

The developer's checkout is **`~/rdp-server/`** and the **only**
persistent build directory is **`~/rdp-server/build/`**. Reconfigure
and reuse it for *all* compiles, tests, profiling and generated outputs.
Subdirectories *within* this root are allowed; additional `build-debug`,
`build-release`, `cmake-build-*`, `tests/build` and external temporary
compile roots are not. Never routinely delete the root or unrelated
artifacts. `docs/compile.md` defines the platform-specific commands.
Hosted CI cannot reuse the owner's home checkout; each ephemeral job is
restricted to one `<checkout>/build` root.

## Minimize fragmentation everywhere

- Exactly one authoritative owner for each connection/session state,
  virtual-channel lifecycle, graphics schedule and clipboard generation.
  No competing controllers or caches.
- Reuse existing first-party C++23 code, fixtures and test helpers.
  Consolidate CTest registration and name tests by behavior rather than
  legacy milestone IDs; do not weaken assertions.
- Keep a portable standards-compliant RDP engine with separate native
  OS adapters. No dependency on xrdp, patched chansrv, VNC/RFB or other
  servers. Respect third-party attributions.
- Prefer RAII, checked `std::span`, contiguous buffers, minimal copies,
  bounded workloads, clear ownership, fail-only logging and measured
  performance. Follow the four standards documents, not ad hoc advice.

## Git, security and delivery discipline

Work on existing `main`. **Never create a new branch** (including
branch-backed worktrees) absent the owner's explicit request. Protect
other work: no blind hard resets, force push, full restore/clean or unsafe
concurrent edits. Check HEAD and worktree before changes and push.
No live desktop/clipboard testing, server activation, service restart,
reboot or production modification without explicit authorization.
Synthetic security tests do not permit authenticated OS admission.
Report first failing protocol boundary and honest verification evidence.
