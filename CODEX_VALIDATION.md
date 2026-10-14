# CODEX_VALIDATION.md — validation ledger and agent contract

Read **[AGENTS.md](AGENTS.md)** on every prompt together with
[VISION.md](VISION.md), the living TODO in
[docs/ROADMAP.md](docs/ROADMAP.md), and the mandatory
[coding](coding_standards.md), [testing](testing_standards.md),
[compilation](compile.md) and [benchmark](benchmark.md) standards.

The detailed acceptance contracts live in `testing_standards.md`.
This file records the evidence, not an alternative test policy.

## Local validation (one reused build root)

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

No second local build folder. GitHub Actions each run from one
ephemeral checkout-local `build/`. Tests are C++23, behavior-named,
reusable and automated; run focused and whole CTest plus cross-platform
CI and documentation-policy gate. Do not mask failures.

## Historical verified snapshot

- Original migrated `main` at
  `77c94c75b467f25c3911912ff4a24690894768c8`:
  [GitHub Actions run 38516048776](https://github.com/k1moradi/RDP-server/actions/runs/38516048776)
  was successful with ten original portable protocol tests.
- The semantic test registry, single build-root guard and documentation
  co-change check passed at
  `3196a764ffbe24482ad131ad6949f1c2c23d44d9` in
  [GitHub Actions run 38535115706](https://github.com/k1moradi/RDP-server/actions/runs/38535115706):
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy jobs.
  CMake now registers ten semantic native protocol tests plus one
  project-policy test. These are **offline library tests**, not
  end-to-end desktop or OS admission acceptance.
- Full former project source and unique implementation progress import remains incomplete; historical Git ancestry is not the goal.
  A green protocol static library is **not** a functional desktop server.

## Per-task evidence

Record exact SHA and modified paths, vision/TODO objective, Microsoft
protocol boundary, exact commands/environment, PASS/FAIL/BLOCKED/NOT RUN
results, first failing transition, safety/ownership constraints,
updated documentation and next milestone. Never turn synthetic
authentication fixtures into a claim of real OS session admission.

## Verified strict local-path policy CI (2026-10-14)

The stricter home-checkout and single-build-root guard in
`e1843b07c8772588f29e45a9b8e328e51c59e2ff` passed all four
[Actions run 38535723210](https://github.com/k1moradi/RDP-server/actions/runs/38535723210)
jobs: Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
CMake enforces the checkout-local `build/` and requires ordinary
non-CI checkouts at `~/rdp-server`; GitHub-hosted CI has a documented
workspace exception. Direct verification on the owner's local computer
remains NOT RUN. No live client or authenticated desktop acceptance is
implied by these green jobs.
