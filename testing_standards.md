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

## TCP connection-request stream regression (2026-10-14)

The existing `transport.preauth-session` suite now covers splitting
the 19-byte X.224 CR at every byte offset, one-byte TCP fragments,
coalesced CR plus TLS bytes (exact consumed length), malformed TPKT
versions, reserved bytes, short/oversize declared lengths, invalid
X.224 type, unsupported security, close and replay rejection. This is
an offline stream-intake test only; no listening socket, real TLS peer,
CredSSP, authenticated desktop or external client is included.
Cross-platform CI results must be recorded in the validation ledger.

## Verified incremental X.224 stream-intake coverage (2026-10-14)

Commit `988938a90f8adbae4e07714ac636af3eb0640011` passed
[Actions run 38536987879](https://github.com/k1moradi/RDP-server/actions/runs/38536987879)
on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
The existing `transport.preauth-session` test now exercises every
split point of a complete X.224 request, byte-at-a-time delivery,
coalesced trailing TLS bytes, size/version/type rejection,
unsupported security and terminal replay/close behavior.
No TCP listener, TLS server, session admission or external client
was exercised; these acceptance categories remain NOT RUN.

## Verified X.224 response-ordering regression (2026-10-14)

The existing `transport.preauth-session` suite also tests that a TLS
completion signal before the Connection Confirm has been fully sent is
rejected, as are failed/partial and duplicate send acknowledgments.
It verifies exactly one completed Confirm allows progression to the
existing *synthetic* TLS stage, but **not** real TLS negotiation or
authenticated desktop access.

**Exact-head PASS:** commit `18262c0e4bf9bc4ecec4c2d56b069d4fc723b1f1`,
[Actions run 38537586258](https://github.com/k1moradi/RDP-server/actions/runs/38537586258)
passed GCC/Linux, Clang/macOS, MSVC/Windows and the documentation gate.
This confirms the new response-write completion checks within the
synthetic C++23 transport tests; it does not validate a TLS provider.

## Incremental MCS stream regression (pending CI)

The consolidated `transport.preauth-session` CTest additionally
covers all 416 ways to split the Microsoft MCS/GCC example fixture,
single-byte delivery, every truncated prefix followed by close,
multiple TPKTs in one decrypted read, invalid version/reserved byte,
short/over-limit length, malformed X.224 type/EOT, corrupted BER and
out-of-order/replayed decrypted input. The diagnostic always closes
after the initial envelope and registers no channels; no real TLS
provider or client was executed.
