# Testing standards — reusable RDP correctness and acceptance

Read [AGENTS.md](../AGENTS.md), [VISION.md](VISION.md), and
[docs/ROADMAP.md](ROADMAP.md) **on each prompt**. This is the
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

## Verified incremental MCS stream regression (2026-10-14)

The consolidated `transport.preauth-session` CTest additionally
covers all 416 ways to split the Microsoft MCS/GCC example fixture,
single-byte delivery, every truncated prefix followed by close,
multiple TPKTs in one decrypted read, invalid version/reserved byte,
short/over-limit length, malformed X.224 type/EOT, corrupted BER and
out-of-order/replayed decrypted input. The diagnostic always closes
after the initial envelope and registers no channels; no real TLS
provider or client was executed.

**PASS:** `49c6006d47476184f7448028cd332e377ec9bd0b`, [Actions run 38541509607](https://github.com/k1moradi/RDP-server/actions/runs/38541509607), CMake configure/build/full CTest on Ubuntu/GCC, macOS/Clang and Windows/MSVC plus documentation-policy. Owner-local build and external clients **NOT RUN**.

## Automated SDK installation and consumer acceptance (2026-10-14)

The same consolidated CI compiles/tests Debug and Release for all three
operating systems. For Release it stages installation in the current
build root and configures a small **separately built downstream consumer**
under `build/consumer`. That consumer must find the installed package
with `find_package(RDPServerProtocol CONFIG REQUIRED)`, link
`RDPServer::protocol` and execute a real X.224 parser call.
This tests relocatable CMake metadata and linkage, NOT a TCP listener.
CPack ZIP archives and SHA-256 manifests are delivered only after all
runner-local gates succeed; tagged prerelease publication waits for
all OS jobs and documentation checks. A protocol library archive
is never a substitute for real-client, NLA or desktop acceptance.

## Verified automated release-package smoke gates (2026-10-14)

Commit `1aa025960288d40f476e85c5a9c5f97b06bebf20`
[Actions run 38543429777](https://github.com/k1moradi/RDP-server/actions/runs/38543429777)
passed the full Debug and Release CTests, separately compiled and
executed the installed SDK consumer, and uploaded a CPack ZIP and
SHA-256 manifest on each of Linux/GCC, macOS/Clang and Windows/MSVC;
documentation-policy PASS. These are **offline packaging and link
checks** only. GitHub Release publication is NOT RUN pending an
explicit version tag; authenticated RDP host deployment is unavailable.

## Portable CMake script-mode checks (2026-10-14)

CTest executes the project-policy verifier with `cmake -P`.
Standalone CMake script mode does not necessarily inherit the
configuring project's minimum policy version: `if(IN_LIST)` without
CMP0057 NEW can reject valid syntax. Use policy-independent
`list(FIND ... index)` for set membership in these scripts, or
explicitly declare the script's required minimum CMake version.
Preserve the root layout assertions and check all hosted toolchains.

**PASS after correction:** commit
`f68d1d417424823eed7856761ff95f0ebe1eabb2`,
[Actions run 38544988535](https://github.com/k1moradi/RDP-server/actions/runs/38544988535)
passed policy and full Debug/Release protocol tests, downstream
consumer installation and packaging on all three hosted OSes.
This verifies the policy-independent root document membership check.

## Real OpenSSL handshake evidence (pending exact-head CI)

`transport.preauth-session` constructs an ephemeral EC P-256 key
and self-signed X.509 certificate **in memory**, performs actual
OpenSSL client/server TLS negotiation across a BIO pair, and tests
that only the completed server SSL object can pass the stream
boundary after the entire X.224 reply. It rejects unfinished,
client-role, null, premature and repeated transitions. The fixture
does not validate certificate trust, CredSSP, user credentials
or an OS session. Hosted Linux/macOS/Windows Debug/Release
CTV and package gates remain to be verified on this commit.

**Exact-head PASS:** `edfaf2e7ea684ab5adc77bf58441ff467288f818`,
[Actions run 38551496274](https://github.com/k1moradi/RDP-server/actions/runs/38551496274)
passed all Debug and Release protocol and policy CTests, nested
downstream install/consumer CTest, and CPack SDK packaging on
Linux/GCC, macOS/Clang, Windows/MSVC, as well as documentation-policy.
No live network client, OS admission or external server was tested.

## In-memory encrypted TLS record intake (CI pending)

Extend existing `transport.preauth-session`, not the test executable
registry. Use an ephemeral self-signed test certificate and an OpenSSL
memory BIO pair, send actual encrypted application records over
`SSL_write_ex`, and exercise `SSL_read_ex` on the server side for
every split position of the Microsoft 416-byte MCS/GCC fixture.
Assert WANT_READ retry, precise consumed plaintext bytes,
coalesced next-PDU preservation, malformed header rejected after
exactly four decrypted bytes, wrong/foreign SSL handle rejection,
premature transitions, orderly TLS close and terminal replay.
This is only a test of authenticated *record integrity* within TLS,
not CredSSP credentials, certificate enrollment, a TCP server, or
independent OS desktop authorization.

**Verified encrypted-record regression (2026-10-14):**
commit `a226f15827e9da48ad7a91b7cfa53528c3498802`,
[Actions run 38557465241](https://github.com/k1moradi/RDP-server/actions/runs/38557465241)
passed on Linux/GCC, macOS/Clang and Windows/MSVC, plus the
documentation-policy job. The same `transport.preauth-session`
CTest exercises all 416 fragment splits as real TLS application
records, WANT_READ retry, exactly bounded TPKT consumption,
coalesced follow-up packet retention, swapped TLS handles, invalid
header and TLS close_notify during a truncated envelope. All
Debug/Release CTests and SDK install/consumer/package gates passed.
Live sockets, CredSSP/NLA and OS admission were NOT RUN.

## Verified granular behavior-named CTest reporting (2026-10-14)

`ctest` counts registered test commands, **not assertions or loops**.
Previously `transport.preauth-session` was one registered test even
though its native executable ran ten behavior groups (including all
416 Microsoft fixture TLS split points), so the visible total
remained 11. Register those groups individually via **one existing
test executable**, one CMake test registry and distinct command-line
case arguments. Preserve every existing assertion and keep direct
no-argument execution as the complete suite. A mistyped/unknown case
name exits nonzero. Expected CTest registration:
**20 tests** (nine other native test executables, ten preauth
behavior cases and one project-policy test). This count measures
reporting granularity, not server protocol coverage or authorization.

**Verified:** exact code commit
`1e11327f2b74ff7e676fbb3bb7200491718a779f`,
[Actions run 38559221423](https://github.com/k1moradi/RDP-server/actions/runs/38559221423)
passed Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
Ubuntu's full Debug and Release CTest logs each report **20/20 PASS**;
all three platform SDK install/consumer and ZIP checks passed. No
owner-local post-change run, external client or OS admission was tested.

## Verified exact X.224 partial-write regressions (2026-10-14)

The existing `test_owned_preauth_session` executable registers
a new independent `transport.x224-confirm-partial-writes`
CTest. Verify every 0..19-byte split of the full Confirm,
every one-byte send, an EAGAIN/zero write, suffix exactness,
a partial-write TLS attempt, overreported positive counts,
terminal writer cancellation, post-completion replay and
an entirely delivered failure PDU followed by close.
The preexisting 20 CTests remain, making **21 registered
cases** with the same binary/fixture ownership. This measures
real additional wire-output behavior, not extra fake coverage
or successful network authentication.

**PASS:** code commit `98f6fdc60d513d47a87a78fadf1aa6be387da28b`,
[Actions run 38561127854](https://github.com/k1moradi/RDP-server/actions/runs/38561127854)
on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
Debug/Release CTests, installed SDK consumer and all platform
ZIP/checksum gates passed. Ubuntu logged **21/21 PASS** twice.
Live network, external clients, NLA and OS admission are NOT RUN.

## Verified nonblocking TCP preauthentication adapter (2026-10-14)

The existing `test_owned_preauth_session` executable adds two
independent behavior-named CTests: `transport.tcp-adapter-fragments`
and `transport.tcp-adapter-backpressure`. A scripted socket interface
simulates exact partial recv/send progress, would-block, every split
of the 19-byte Connection Request, one-byte reads/writes,
coalesced ClientHello preservation, rejected negotiation Failure
output, malformed TPKT, EOF/hard read/write failures, invalid
overreported byte counts and terminal connection closure.
The native Winsock and POSIX adapters are cross-compiled but not
connected to an active OS TCP listener by this regression.
Expected CTest total **23**, previously 21; authentication, actual
network peers, TLS network pump and desktop remain NOT RUN.

**PASS:** code commit `dd3a806f97b13e6db18affd689c6321bfa009813`,
[GitHub Actions run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
passed Ubuntu/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release full CTests, staged SDK install, downstream consumer
and all three ZIP/hash uploads. Ubuntu logs confirm
**23/23 passing** in both builds. The native OS recv/send
implementation compiles on all three platforms; scripted
TCP I/O, not connected live sockets, drives the new tests.

## OpenSSL 4 X.509 fixture compatibility (2026-10-14; CI follow-up)

[Actions run 38564061700](https://github.com/k1moradi/RDP-server/actions/runs/38564061700)
failed macOS/Clang Debug compile because Homebrew's FindOpenSSL
selected OpenSSL **4.0.3**; `X509_get_subject_name` supplies a
`const X509_NAME*` in this release, and mutating it is forbidden.
The offline TLS fixture now uses its own RAII `X509_NAME_new()`,
`X509_NAME_add_entry_by_txt()`, then
`X509_set_subject_name()` and `X509_set_issuer_name()` to
construct the self-signed ephemeral certificate. This avoids
casting away `const` and is compatible with OpenSSL 3 and 4.
The test still does not establish live certificate trust.

**PASS:** fixed implementation `5c4f3ad7273d17948327b7d351ff9840de2b0395`
[GitHub Actions run 38564403002](https://github.com/k1moradi/RDP-server/actions/runs/38564403002)
completed Linux/GCC, macOS/Clang and Windows/MSVC
Debug/Release **23/23 CTests**, documentation-policy, staged SDK
installation and downstream consumer, and three ZIP/checksum uploads.
The macOS passing runner used OpenSSL **3.6.4**, not 4.0.3; a
post-fix test specifically linked against OpenSSL 4 remains
**NOT RUN**. Preserve explicit version evidence rather than
calling an API change verified across both versions.

## Verified nonblocking OpenSSL server TLS handshake owner (2026-10-14)

Two behavior-named CTests in the **existing** preauth binary,
`transport.tls-nonblocking-handshake` and
`transport.tls-nonblocking-failures`, exercise a real
in-memory OpenSSL client/server TLS handshake via BIO pair
driven by the new one-owner event-loop handshake method.
Assert WANT_READ before ClientHello, further nonblocking
progress, eventual completed server-role TLS, and use of the
same SSL for the bounded 416-byte MCS/GCC envelope.
Negative gates: premature TLS before the X.224 response
is sent, null/client-role handle, foreign server-handle swap
after WANT_READ, explicit cancellation/replay, and
unusable socketless SSL. Expected **25 total registered
CTests**, up from 23 for two independent behaviors. These
tests use a synthetic in-memory certificate and do not
validate certificate trust, socket runtime, CredSSP,
desktop authorization or external RDP clients.

**PASS:** exact implementation
`fcd05f8e903a459ca85f13807bd35f7091f3fd70`
in [CI run 38566584099](https://github.com/k1moradi/RDP-server/actions/runs/38566584099):
Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
both Debug/Release **25/25 CTests**, staged SDK install,
downstream compiled/linked/running consumer and all three CPack
ZIP/checksum uploads. The TLS event-loop handshake is verified
against an in-memory BIO peer, not a native TCP socket or real
RDP client. An explicit OpenSSL 4.x post-fix runner is still
NOT RUN; see the compatibility gate above.

## Verified real native TCP loopback TLS/MCS transport (2026-10-14)

The existing `test_owned_preauth_session` CTest registry adds two
independently named behaviors without duplicating the executable:
`transport.tcp-native-loopback-tls` and
`transport.tcp-native-loopback-close`. Each test creates a
short-lived, OS-assigned ephemeral loopback port, connects one
client, accepts one server socket, and closes its temporary
listener before protocol traffic. The first exchanges real
TCP X.224 Request and Confirm using `NativeTcpIo`, attaches
OpenSSL through the borrowed custom BIO on **both peers**,
drives a TLS server handshake with WANT readiness, sends a
real encrypted Microsoft 416-byte MCS/GCC example and validates
the envelope without OS admission. The second verifies real
native EOF during a truncated Connection Request and a complete
protocol Negotiation Failure over connected sockets, with no TLS.
All socket resources are RAII/closed. Expected full CTest
registration: **27**, formerly 25. **PASS:** after the test-only readiness fix at
`7ce64737ccef439af2f0cfd383208181cc0e9513`,
[Actions run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
passed Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release **27 CTests** on all OSes, staged SDK installation,
downstream consumer and platform package/checksum uploads.
Ubuntu's full CTest logs explicitly show **27/27 PASS** in both
build modes, including both native socket cases.
External RDP clients, credential verification, OS desktop admission
and service deployment are NOT RUN.

## Deterministic loopback event readiness (2026-10-14)

**First CI FAIL:** implementation
`c53a591c8d5b6dbb4cd63f742bddb2c3eeb2ede8`,
[run 38578878083](https://github.com/k1moradi/RDP-server/actions/runs/38578878083)
reported both `tcp-native-loopback-*` CTests failing on
macOS Debug due to an incorrect test assumption: after TCP
send or close, the very next nonblocking recv need not
observe the bytes or FIN. Ubuntu and Windows plus
documentation-policy passed. Test-only code now waits
a bounded number of short 1ms intervals until the exact
expected read/EOF readiness event, verifies the expected
prefix was actually consumed before client close, and
still fails if it never occurs. Do not hide native
callback errors or spin in production code.
**PASS after correction:** full cross-platform Debug/Release
27-CTest matrix, downstream SDK consumer and three packages in
[Actions run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
at `7ce64737ccef439af2f0cfd383208181cc0e9513`.
The owner's new local run and real external clients remain NOT RUN.
