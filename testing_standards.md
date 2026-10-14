# Testing standards — reusable RDP correctness and acceptance

Read [AGENTS.md](AGENTS.md), [VISION.md](VISION.md), and
[docs/ROADMAP.md](docs/ROADMAP.md) **on each prompt**. This is the
single authoritative testing policy; record new acceptance lessons here.

## Reusable semantic suites

Use **one** CTest registry in `tests/CMakeLists.txt`; extend the existing
compiled C++23 tests and shared bounded fixtures, rather than creating
separate test runners per agent/milestone. CTest names indicate behavior:
`transport.x224`, `transport.mcs-connect-initial`,
`security.credssp-binding`, `clipboard.remote-transfer`.
Labels include `protocol`, `transport`, `security`,
`clipboard` and `project-policy`. Preserve source filenames where
renaming has no functional benefit. Prefer tests against production
translation units, not text-pattern assertions or pure mocks.

## Mandatory automated gates

- Configure/build/run full CTest from the same reused
  `~/rdp-server/build/`. Use `ctest -R`/`-L` for focused work;
  full suite before claiming implementation success.
- Run cross-platform C++23 compile and CTest in GitHub Actions on
  Linux/GCC, macOS/Clang and Windows/MSVC, one checkout-local CI
  `build/` per job. Fix failures instead of hiding or skipping them.
- Every protocol parser covers valid, truncated, malformed, unknown
  capability, oversized and integer-overflow cases; every state
  machine covers ordering, stale responses, cancel/disconnect and
  lifetime/cleanup. Validate credentials and channel boundaries.
- Add supported ASan/UBSan and bounded fuzzing as implementation
  progresses; document toolchain gaps rather than claiming coverage.
- CI checks for documentation co-changes; an offline policy CTest
  checks mandatory sources. Humans still verify that TODO and evidence
  are materially accurate.
- Real external clients and Linux/macOS/Windows desktop acceptance
  require separately authorized host experiments and recorded client
  versions/capabilities. A simulated FreeRDP peer is not automatically
  a normative Microsoft implementation.

## Acceptance criteria and reporting

| Feature | Offline coverage | Real acceptance gate |
| --- | --- | --- |
| Connection | X.224/TPKT/MCS/GCC parsers/state | Real-client negotiated handshake |
| Security | TLS/CredSSP/DER/binding rejection | Authenticated AND OS-authorized session |
| Session | Licensing/share/virtual-channel lifecycle | Usable client session and clean disconnect |
| Graphics/input | Frame, codec, queues and input tests | Interactive visible desktop |
| Clipboard | Format/generation/PNG/DIB/file tests | macOS screenshot to Firefox non-null PNG File |
| Installation | Cross-OS packages/adapter tests | Secure standalone server deployment/rollback |

Label every gate **PASS/FAIL/BLOCKED/NOT RUN**, with commit SHA,
exact command/environment, first failing boundary and next TODO.
A green static-library test never proves a complete RDP server.

```sh
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
ctest --test-dir "$HOME/rdp-server/build" -C Debug -L security --output-on-failure
```

## Verified policy and cross-platform CI baseline (2026-10-14)

[GitHub Actions run 38535115706](https://github.com/k1moradi/RDP-server/actions/runs/38535115706)
passed Linux/GCC, macOS/Clang, Windows/MSVC and the documentation-policy
job at commit `3196a764ffbe24482ad131ad6949f1c2c23d44d9`.
CMake registers ten behavior-named C++23 protocol tests and a project
policy check. Do not infer external-client functionality, real session
authorization or desktop/clipboard usability from these tests.
