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

**All development, fixes, tests, documentation and commits MUST take place
on the existing `main` branch. Creating ANY other Git branch is prohibited
for everyone**, including temporary, feature, hotfix, release, experimental
and agent-specific branches, local or remote. Do not create branches through
Git commands, worktrees, GitHub APIs, pull-request automation or other tools.
Do not commit development work on detached HEAD or publish it to a side
branch. Release tags may reference verified commits already on `main`;
tags do not authorize branch creation.

**Direct-to-main delivery is mandatory, not patch-only work.** Each agent
implements its assigned increment, registers at least one new dedicated
behavior-named CTest for production-code changes in the shared test
registry, updates the canonical TODO and affected documentation, and
**publishes all changes together as one commit directly to GitHub `main`**.
Do not stop after drafting patches, code snippets, proposed diffs or a
handoff to R10 when commit access is available. R10 coordinates integration
and may review commits, but is not a required approval or publication
bottleneck.

**Concurrent writers use optimistic, non-force fast-forward updates.**
Immediately before committing/publishing, fetch current remote `main`
HEAD and affected files. Construct an atomic code+CTest+docs commit on
that HEAD and update `main` only if HEAD is still the expected SHA.
If another agent commits first, fetch the newer `main`, reconcile your
changes without discarding theirs, rerun affected checks when available,
and retry the atomic direct-to-main commit. Never force-push, blind-reset,
overwrite another agent's work, create a branch or silently publish stale
files. Report BLOCKED only for a real unresolved conflict, missing write
permission or other concrete technical blocker, with the attempted steps;
do not treat absence of an R10 slot as a blocker.

**The owner's exact command must work on freshly pulled `main`:**
`cd ~/rdp-server && git switch main && git pull --ff-only origin main && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON && cmake --build build --config Debug --parallel 2 && ctest --test-dir build -C Debug --output-on-failure`.
Every applicable new CTest must run under ordinary full CTest without
requiring live desktop, clipboard, credentials, service modification or
interactivity; native-only tests are conditionally registered. Agents
are responsible for fixing introduced build/test failures, not the owner.
The owner runs this command on Linux/X11, Windows MSYS2 CLANG64/Clang 23
and macOS 27 and reports results. Record tested SHAs for each platform;
when all three reports cover different SHAs, do not assert same-SHA
milestone acceptance. Publication to `main` need not wait for the owner
to run tests; do not claim platform PASS before receiving reports.
No blind hard resets, force pushes, full restores/cleans or unsafe
concurrent edits. Check HEAD and worktree before each publication.
No live desktop/clipboard testing, server activation, service restart,
reboot or production modification without explicit authorization.
Synthetic security tests do not permit authenticated OS admission.
Report first failing protocol boundary and honest verification evidence.
