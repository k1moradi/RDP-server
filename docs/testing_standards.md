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

## Clipboard verification gates (planned; NOT RUN)

Extend the existing behavior-named CLIPRDR/PNG/DIB tests instead of adding
an independent clipboard test runner. Offline tests must cover:

- Capabilities and named-format mappings (`PNG`, `FileGroupDescriptorW`,
  Unicode text, DIBV5/DIB), valid and malformed format lists, responses,
  fragmented channel PDUs, overflow, limits and unsupported formats.
- One outstanding ordinary Format Data Request, fresh/new generations,
  delayed/stale replies, reoffers, timeout ambiguity, disconnect, retry,
  cancellation, and memory ownership. An old response must never satisfy a
  new-generation paste; `streamId` applies to file contents, not to
  ordinary Format Data Responses.
- PNG signature/chunk/CRC and decompressed-size limits, invalid DIB layouts,
  compressed PNG retention, lazy DIB/PNG conversion and bounded memory.
  Image decoding and conversion must not block the session event thread.
- Asynchronous readiness for text and images: paste-before-prefetch,
  completion, timeout, bad input, clipboard replacement, owner loss,
  concurrent local copy, INCR boundaries and cancellation without deadlock.
- X11 selection owner-change ordering, timestamps, self-echo suppression,
  Qlipper-like selection reownership, `PRIMARY` isolation, loop prevention
  and no timer-driven CLIPBOARD reclaim.
- File descriptor lists and streamed file size/range requests with distinct
  stream IDs, non-sequential chunks, >4 GiB metadata, path traversal, lock/
  unlock and disconnect, bounded transfer buffers and **no whole-file cache**.

Real-client acceptance (separately authorized) must test Windows App
on macOS and Windows 11, local-to-remote and remote-to-local text, PNG/DIB
screenshots and file copy/paste. Include the observed macOS case where a
screenshot taken while Windows App is unfocused is not announced until
refocus; record the actual timing rather than assuming a protocol guarantee.
For the Linux/X11 Firefox paste, inspect the synchronous event:
`clipboardData.items[]` must include a file item whose `getAsFile()`
is non-null, type `image/png`, with the expected image. Generic `xclip`,
X11 selection or CLIPRDR unit success is **not** acceptance. Also test a
paste requested before transfer/conversion finishes, Qlipper competition,
large INCR, file-manager destination integration, lock/cancel, slow links,
and clipboard changes during transfer. Distinguish `PASS` from
`BLOCKED/NOT RUN` with client versions, environment and exact SHA.

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

## MCS Connect-Initial domain negotiation (CI pending)

Reuse `tests/test_owned_mcs_connect_initial.cpp` and the existing
Microsoft 416-byte fixture; no new test binary or runtime
connection controller. Test the eight-field
`mergeMcsDomainParameters` against the documented 34/3/65528
domain result, target/min/max fallback paths, protocolVersion
2 bracketed by non-2 min/max BER values, and each of eight
failure branches with zeroed result. Also feed an otherwise
valid Connect-Initial with mutually incompatible protocol
versions into the existing preauthentication diagnostic and
assert terminal invalid framing/close.
Register the four existing envelope behaviors individually
and two new domain behaviors as six CTests in the canonical
test registry: expected total **32** vs 27 (two new
behaviors, four existing now registered separately instead
of one group). Preserve no-argument execution of all six tests.
An offline domain merge is not an MCS Connect-Response, an
authenticated server or live-client acceptance.

## Standalone response-wire encoder, not admission (CI pending)

Keep the existing `tests/test_owned_mcs_connect_initial.cpp`
binary and the centralized `tests/CMakeLists.txt` registry.
Add `transport.mcs-response-wire` with a complete independent
**108-byte** Enhanced TLS Connect-Response/GCC golden packet
based on Microsoft [4.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3):
exact TPKT/BER/PER lengths, McDn and SC_CORE/NET/SECURITY,
including three channel assignments and odd padding.
Also exercise upper-bound T.124 nodeID and BER sign padding
for a 32-bit domain parameter.
`transport.mcs-response-rejections` must reject illegal node IDs,
unsupported security protocols, missing/mismatched/duplicate or
reserved channels, an unmergeable domain and missing GCC
client data, returning no serialized bytes.
Expected full CTest registration **34**, up from 32.
The older parser suites remain active; no code path may
send a response or claim credential/OS admission from these
offline tests.

## Verified offline MCS Erect/Attach/ChannelJoin request regressions (2026-10-14)

In the existing `test_owned_mcs_connect_initial` binary, register
three additional behavior-named CTests without another executable:
`transport.mcs-erect-request`, `transport.mcs-attach-request`,
`transport.mcs-channel-join-request`. Use independent literal
TPKT/X.224/PER wire oracles from Microsoft's published
MS-RDPBCGR 4.1.5, 4.1.6 and 4.1.8.2.1 examples, plus 4.1.8.5.1
for channel 1006. Each test checks all byte-boundary
truncations and malformed framing, payload surplus, invalid
PER integer lengths/nonminimal values, UserId overflow,
wrong direction/choice padding and preservation of valid
channel identifiers without falsely calling them joined.
The previous 34 CTests remain; expected **37 CTests**.
Live phase ordering, authorization, send/confirm responses,
client interoperability and authenticated OS session
admission remain **NOT RUN**.

**First CI regression (2026-10-14):** the new wide-field Erect
example in `testMcsErectDomainRequest` mistakenly encoded
`0x04` as the byte length of a three-byte subInterval.
The strict PER decoder correctly rejected it. Ubuntu's
[run 38588334504](https://github.com/k1moradi/RDP-server/actions/runs/38588334504)
failed `transport.mcs-erect-request`, with 36 other
CTest commands PASS in Debug. Correct the fixture determinant
to `0x03`; preserve the assertion that the resulting value
is 0x010203 and leave production parsing unchanged.
**PASS:** corrected commit
`6effdb76229e2514511ebe5dd8cb404841403b1b`,
[run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653):
Ubuntu/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release full **37 CTests**, installed SDK consumer and
all three ZIP/checksum uploads. Ubuntu logs explicitly
confirm **37/37 passing** in both configurations.
Owner-local corrected tests and authenticated runtime remain NOT RUN.

## Verified offline MCS server confirmation wire tests (2026-10-14)

Add two separate behavior-named CTests to the existing
`test_owned_mcs_connect_initial` binary and shared
`tests/CMakeLists.txt` registry:
`transport.mcs-attach-confirm-wire` and
`transport.mcs-channel-join-confirm`. Compare full
TPKT/X.224/PER frames byte for byte to Microsoft examples:
Attach User Confirm 11 bytes for UserId 1007; Channel Join
Confirm 15 bytes for UserId 1007 and ChannelId 1003.
Check UserId boundary offsets 1001 and 65536 and the
published rdpdr 1004 variant. Reject all invalid IDs,
wrong incoming request type, foreign initiator, empty,
duplicate/omitted, or oversized approval lists, and
nonsensical auxiliary fields. Confirm these server-directed
packets remain invalid as *client* requests in the existing
parser. Full expected CTests: **39**, previously 37. No
positive test grants OS authorization or sends TLS data.

**PASS:** implementation commit
`4eb3bff4f9fc15cb72da1b8e994ec89e7e9a96db` in
[Actions run 38590263498](https://github.com/k1moradi/RDP-server/actions/runs/38590263498)
completed Linux/GCC, macOS/Clang, Windows/MSVC,
documentation-policy, Debug/Release **39 CTests**, installed
downstream SDK consumer and three ZIP/checksum uploads.
Both new independent confirmation-wire cases passed; Ubuntu
logs explicitly show **39/39 PASS** in Debug and Release.
This is protocol syntax verification, NOT authenticated session
admission or real client interoperability.

## Verified incremental TLS-decrypted CredSSP TSRequest DER framing (2026-10-14)

Keep the existing `test_owned_credssp_tsrequest.cpp` executable
and register its previous five behavior groups separately,
plus three NEW tests in the canonical `tests/CMakeLists.txt`:
`security.credssp-stream-fragments` checks every split and
single-byte callbacks against the existing complete DER
parser and borrowed lifetime; `security.credssp-stream-coalesced`
checks byte-exact no-read-ahead, explicit release, DER 0x81,
0x82 and near-limit 16 KiB examples; and
`security.credssp-stream-rejections` checks wrong tag,
indefinite/nonminimal lengths, declared oversize,
semantic-invalid complete DER, interrupted/closed framing
and illegal replay of an unreleased frame. All five former
groups remain callable individually, giving expected
**46 CTests** (39 prior registered, 3 newly implemented
and 4 extra registrations for existing groups). Ensure
default no-argument invocation still executes all eight
groups. Do not use synthetic SPNEGO tokens as evidence of
Kerberos credentials, TLS binding or desktop admission.

**PASS:** exact implementation
`c7f0463a3e11c8bd9fb6e8dfb404c3f1057d40cd`,
[CI run 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562)
passed Linux/GCC, macOS/Clang, Windows/MSVC and
documentation-policy; Debug/Release full CTests,
staged SDK installation, external compiled/linked/ran
consumer, and three platform ZIP/SHA-256 package uploads.
Ubuntu explicitly reports **46/46 PASS** in Debug and Release,
including all three incremental DER-framing cases.
**NOT RUN:** owner-local new build, live TLS NLA,
Kerberos authentication or OS desktop authorization.

## Verified offline CredSSP server DER reply validation (2026-10-14)

Reuse the existing `test_owned_credssp_tsrequest` binary and
register two behavior-named CTests:
`security.credssp-server-reply-wire` and
`security.credssp-server-reply-rejections`.
The former compares complete literal MS-CSSP-compliant v6
NegoData and protected-binding reply bytes, checks v5, DER
length thresholds and exact parser/framer roundtrips.
The latter rejects invalid versions, empty payload, unknown
reply variants and a provider token over 8192 bytes.
**PASS:** implementation `46e77ed65afdd9526ee1c63d39724668670cf047`,
[Actions run 38596955778](https://github.com/k1moradi/RDP-server/actions/runs/38596955778)
completed both Debug and Release **48/48 CTests** on
Linux/GCC, macOS/Clang, Windows/MSVC, plus the
documentation-policy gate, staged SDK consumer smoke tests
and all three platform ZIP/SHA-256 uploads. The prior
baseline had 46 CTests.
**NOT RUN:** owner-local updated build, real GSS, TLS binding,
OS authorization or external clients. Wire serialization
alone does not grant an authenticated session.

## Verified Linux GSSAPI provider negative gates (2026-10-14)

Linux CI installs `libkrb5-dev` and sets
`RDP_SERVER_TEST_LINUX_GSSAPI=ON` in the same `build/` root.
The Linux-only `test_linux_gssapi_spnego` executable registers
`security.gssapi-configuration-rejections` and
`security.gssapi-framed-handoff`. It links the actual
MIT GSSAPI acceptor, binding and deny-only credentials
sources, not a mock authentication provider. The first
test rejects an absent explicit absolute keytab, invalid
service identity, relative keytab, and context reuse;
the second tests rejected unconfigured, partial, v4 and
malformed DER frames with terminal cleanup.
**PASS:** implementation `36989cebcc6a69b51d1c3f3d5d1f2660417a9865`,
[CI run 38603782133](https://github.com/k1moradi/RDP-server/actions/runs/38603782133)
completed **50/50** Linux/GCC CTests and **48/48**
macOS/Clang, Windows/MSVC CTests in Debug and Release.
SDK consumer, ZIP/checksums and documentation-policy
passed across all platforms. No positive GSS login,
OS admission or listener is implemented.
**NOT RUN:** owner-local build, live keytab/ticket,
TLS channel binding, independently authenticated desktop
or external-client acceptance.

## Verified new CredSSP TLS-read regressions (2026-10-14)

Every new production TLS/framing behavior received new tests
in the preexisting `test_owned_preauth_session` binary,
using the real in-memory OpenSSL TLS fixture:
`transport.credssp-tls-fragments` covers all 20 positive
split points with exact bytes-read accounting and released
buffer lifetime; `transport.credssp-tls-coalesced`
exercises two DER frames in a single encrypted TLS record,
no consumption past the current frame, release and
plaintext-injection denial; `transport.credssp-tls-rejections`
checks null/client/unhandshaken/swapped SSL, source mixing
in both directions, invalid DER and truncated TLS EOF.
**PASS:** code `d2885363502e34e52c71c41342902908b781fd58`,
[Actions 38607049062](https://github.com/k1moradi/RDP-server/actions/runs/38607049062):
Debug/Release Linux/GCC **53/53**, macOS/Clang
**51/51**, Windows/MSVC **51/51** CTests and all
three added tests on each. Linux-only GSSAPI provider
regressions remain PASS. SDK consumer, per-OS package
ZIP/checksum uploads and documentation policy PASS.
**NOT RUN:** owner-local tests, real Kerberos/TLS
public-key binding, independently authorized OS session,
Microsoft client or interactive desktop. No release tag.

## Verified new TLS/GSS provenance tests (2026-10-14)

All new C++ code received new, behavior-named regression
coverage without a second TLS certificate fixture. The
preexisting `test_owned_preauth_session` OpenSSL memory-BIO
fixture drives `transport.credssp-tls-provenance` on
all platforms: manual DER has no TLS source, partial
frames have no completed source, the complete frame
carries exactly the live server SSL, and release/close
clears its exposed provenance. The same binary links
the real optional MIT GSSAPI provider on Linux and
registers `security.gssapi-tls-ownership`: both
v5 and v6 fabricated GSS tokens transported over
real TLS, caller-injected DER, and unverified protected
binding fail without credentials, outputs or admission.
**PASS:** exact implementation `6e11b25224e1a5e6c3f45778436afc3950a3e866`,
[Actions 38609620612](https://github.com/k1moradi/RDP-server/actions/runs/38609620612)
on Linux/GCC **55/55**, macOS/Clang and Windows/MSVC
**52/52** Debug and Release CTests, installed SDK
consumer, CPack ZIP/SHA-256 artifact uploads for all
three systems and documentation-policy. The earlier
Ubuntu Release `-Wstringop-overflow` warning in
`tests/test_owned_preauth_session.cpp:587` is
preexisting and nonfatal. **NOT RUN:** owner's
local build, positive GSS Kerberos credential/keytab,
TLS pubKeyAuth, OS admission or real clients. Synthetic
negative evidence is not desktop authorization.

## Verified final combined CredSSP handshake tests (2026-10-14)

Three additional CTest groups were registered WITHOUT
removing any existing group. Reuse the existing
`test_owned_credssp_tsrequest` executable for
`security.credssp-final-negotiation-binding`
(positive v5/v6 canonical DER, borrowed token/nonce/
ciphertext, every byte-fragment boundary, oversized
request rejection) and
`security.credssp-final-binding-rejections`
(missing fields, credential/error mixing, nonce
sizes, v2/v4 downgrade, multiple tokens,
oversize pubKeyAuth and malformed DER).
Reuse the existing `test_owned_preauth_session`
memory-BIO TLS fixture for Linux-only
`security.gssapi-final-combined-denials`
with the *real* linked MIT GSSAPI provider,
fabricated final v5/v6 frames over completed TLS,
terminal denial, replay denial and manual/partial
frame rejection. The tests do NOT simulate a
successful authenticated GSS context.
**PASS:** implementation
`ad848646391eb7f2dce5c8e2a6238212e7f4e5ae`,
[Actions 38612269453](https://github.com/k1moradi/RDP-server/actions/runs/38612269453):
Linux **58/58**, macOS/Windows **54/54** CTests,
both Debug and Release; the three new cases passed.
All three OS SDK downstream consumers, ZIP/checksum
artifact uploads and documentation-policy PASS.
**NOT RUN:** owner's updated local build, real
Kerberos tickets/keytab, successful GSS pubKeyAuth
exchange, independently authorized OS sessions,
Microsoft client or live desktop. The previously
reported unrelated Ubuntu Release warning at
`tests/test_owned_preauth_session.cpp:587`
remains nonfatal.

## Verified CredSSP TLS reply wire and backpressure regressions (2026-10-14)

Reused the existing `test_owned_preauth_session`
real in-memory OpenSSL TLS fixture and executable.
Three new named CTests pass:
`transport.credssp-tls-reply-wire` tests
canonical v6 negoToken/binding replies with
payload lengths 1/127/128/256/8192, exact
client-decrypted DER bytes, owned provider-output
snapshot, completion idempotence and safe reuse;
`transport.credssp-tls-reply-backpressure`
forces real WANT_WRITE via a 2048-byte BIO created
BEFORE pairing/handshake while sending an
8192-byte opaque output, and verifies stable
SSL retries, exact once-only plaintext delivery
and total byte accounting;
`transport.credssp-tls-reply-rejections`
covers null, unhandshaken and client-role SSL,
unsupported versions, empty/oversized payload,
TLS substitution, duplicate pending reply and
terminal close. No CTest or assertion was removed.

**Initial FAIL:** implementation
`915cd2bfac59d7e775b458b7deed3d94db17ad93`,
[CI 38614500856](https://github.com/k1moradi/RDP-server/actions/runs/38614500856),
attempted to resize an existing BIO pair after
TLS handshake; macOS (and Linux) Debug fixture
setup failed before WANT_WRITE. **PASS:** corrected
fixture at `afa7d737b4ee32c0f0e72bbedd32e6cb9066afd6`,
[CI 38614808824](https://github.com/k1moradi/RDP-server/actions/runs/38614808824):
Linux/GCC **61/61**, macOS/Clang and Windows/MSVC
**57/57** CTests each Debug and Release,
including all three new test groups on all
systems. Downstream SDK install/consumer,
ZIP/SHA-256 package uploads and documentation
policy PASS. Preexisting unrelated Ubuntu
Release test source `-Wstringop-overflow` warning
at `tests/test_owned_preauth_session.cpp:589`
is nonfatal.
**NOT RUN:** owner-local build, positive GSS
Kerberos, TLS binding, independently authorized
OS session or Windows App interactive desktop.

## Verified real-provider CredSSP TLS reply safety tests (2026-10-14)

Three NEW Linux-only security CTests reuse
the original real OpenSSL memory-BIO TLS fixture
with the actual linked MIT GSSAPI target:
`security.gssapi-negotiation-reply-gates`
asserts v5/v6 TLS-derived initial requests,
replay and synthetically injected DER cannot
produce a server GSS `negoTokens` reply
without a configured positive Kerberos context;
`security.gssapi-binding-reply-gates`
asserts that v5/v6 combined final
`negoTokens+pubKeyAuth` frames cannot queue
a server GSS-wrapped binding without actual
provider verification, and manual/partial
DER remains rejected;
`security.gssapi-reply-order-denials`
proves a pending unflushed server TLS reply
blocks another client token and causes
terminal reader/writer/GSS cleanup with NO
client-readable TLS response. The existing
all-platform GSS framing, TLS writer,
credential and binding assertions remain
unaltered.

**PASS:** exact code commit
`27e8342aee0e475c3b0854330678e7c7596fc912`,
[Actions run 38617602493](https://github.com/k1moradi/RDP-server/actions/runs/38617602493)
all four required jobs passed:
Linux/GCC **64/64**, macOS/Clang and
Windows/MSVC **57/57** CTests in both
Debug and Release, including all 3
new Linux-only cases; installed SDK
consumer, ZIP/SHA256 artifact upload
and policy PASS.
**NOT RUN:** owner-local tests,
positive service keytab/TGT,
successful GSS confidentiality/TLS
pubKeyAuth, independent OS
user authorization, actual client
or interactive desktop. The
preexisting nonfatal Ubuntu Release
test warning at line 589 remains.

## Verified real-TLS selected certificate binding and pinning tests (2026-10-14)

Three NEW named CTests in the same existing
`test_owned_preauth_session` executable and
ephemeral EC X.509 OpenSSL memory-BIO TLS
fixture exercise the actual selected TLS
certificate, rather than fabricated X509/GSS
identities. `security.credssp-active-tls-binding-positive`
compares both v5/v6 direction-specific
32-byte nonce hash results against
`computeCredSspBindingHash` independently
using the active selected X509
SubjectPublicKey BIT STRING, and confirms
the certificate SHA-256 fingerprint.
`security.credssp-active-tls-binding-rejections`
rejects different live server certificates,
every nonce/hash mutation, reflected
server-to-client hash, null/client-role or
unfinished SSL, malformed nonce/hash lengths,
and checks cleared output on failure.
`transport.credssp-tls-certificate-pinning`
modifies the selected X509 ON THE SAME SSL
after a completed DER frame and during
a partial frame. The TLS provenance must
disappear, reads must reject and wipe
the existing reader; a stable certificate
must remain valid after repeat frame
release. There is no GSS-success assertion
or OS login authorization.

**Initial CI FAIL:** initial
`d0583c92eb6b6a3517d5e96ea5fd8adc07ee413d`,
[CI 38619291326](https://github.com/k1moradi/RDP-server/actions/runs/38619291326):
test compile attempted to give an OpenSSL 4
`const X509*` to `SSL_use_certificate`
which expects a mutable test-owned `X509*`.
**Corrected implementation:** exact
`340ce518d0e84ea94a4d24c295f8fa88e74ccf6d`,
uses `X509_dup` and existing test-owned
`CertificatePointer` with equivalent
selected SHA-256 fingerprint assertion.
No negative security assertions removed.

**PASS:** [Actions 38619544190](https://github.com/k1moradi/RDP-server/actions/runs/38619544190):
Linux/GCC **67/67**, macOS/Clang and
Windows/MSVC **60/60** CTests, each
Debug+Release, all 3 new groups PASS,
SDK downstream consumer, ZIP/SHA256 package
uploads and documentation-policy PASS.
The preexisting unrelated Linux Release
test compiler warning remains nonfatal.
**NOT RUN:** owner's local new build,
actual positive keytab/Kerberos ticket
and confidential GSS TLS pubKeyAuth,
independently authorized OS session,
real Microsoft client or desktop.

## Verified Linux TLS-framed GSS binding-only regressions (2026-10-14)

Two new Linux-only real OpenSSL memory-BIO
TLS and linked MIT GSSAPI behavior CTests
reuse the existing `test_owned_preauth_session`
executable:
`security.gssapi-framed-binding-only-denials`
delivers a syntactically valid binding-only
v5/v6 DER message through TLS, confirms
the pinned SSL provenance, then requires
denial without a real verified GSS context.
Legacy raw caller DER, manually consumed
DER, incomplete DER and replay fail
terminally, wiping buffered ciphertext.
`security.gssapi-framed-binding-reply-order`
checks that neither unverified TLS binding
nor a preexisting unflushed server reply
can produce a server application record,
and GSS, framed TLS reader and guarded
reply writer all close on rejection.
The combined-final client token+binding
positive syntax and negative GSS tests,
plus all previous portable SDK suites
remain unchanged.

**PASS:** exact implementation
`340b25d2352314003053ec19d467b75d578c9dbf`,
[Actions 38623829568](https://github.com/k1moradi/RDP-server/actions/runs/38623829568),
Linux/GCC **69/69** and macOS/Clang,
Windows/MSVC **60/60** full CTests in BOTH
Debug and Release; both new Linux
security tests passed. Installed SDK
consumer, all 3 ZIP/SHA-256 artifact
uploads and documentation policy PASS.
Prior unrelated nonfatal Ubuntu Release
test warning near `test_owned_preauth_session.cpp:590`
remains. **NOT RUN:** owner's local build,
real positive Kerberos with ticket/keytab,
successful GSS-protected public-key proof,
independently authorized OS identity,
external client or interactive desktop.

## Verified outgoing CredSSP TLS certificate substitution (2026-10-14)

Three NEW all-platform behavior-named CTests
in the existing `tests/test_owned_preauth_session.cpp`
use real OpenSSL memory-BIO server and
client handshakes. The same SSL object
is reconfigured with a certificate
duplicated via RAII `X509_dup` from
an independent completed TLS fixture;
assert that the replacement has
the expected selected SHA-256 fingerprint.
`transport.credssp-tls-reply-cert-pending`
queues v5/v6 `negoTokens` or protected
`pubKeyAuth` and requires failure,
no plaintext transmitted, secure
wipe and no reuse if selected X.509
changes before the first write.
`transport.credssp-tls-reply-cert-completion`
requires terminal mismatch detection
after Complete (both release and
idempotent write paths) or following
release before next queue, and checks
unchanged-certificate multiple replies
still succeed. It does NOT pretend
an already sent TLS reply can be
retracted after certificate change.
`transport.credssp-tls-reply-cert-backpressure`
creates the server BIO with 2048-byte
capacity BEFORE pairing, forces REAL
WANT_WRITE while sending an 8192-byte
canonical server response, changes
the certificate ON THE SAME SSL pointer,
and checks no further TLS write retries
and terminal cleanse. No assertions
were disabled or weakened.

**PASS:** implementation
`53184c7e4fdfb1c01f287933ff4ca0a6fdf63c0a`,
[Actions 38674532102](https://github.com/k1moradi/RDP-server/actions/runs/38674532102):
Linux/GCC **72/72** CTests in BOTH
Debug and Release, macOS/Clang and
Windows/MSVC **63/63** each Debug
and Release, all 3 new cases PASS.
SDK installed downstream consumers,
ZIP/SHA256 packaging and uploads,
and documentation-policy PASS.
Existing unrelated Ubuntu Release
test warning at `tests/test_owned_preauth_session.cpp:590`
remains nonfatal. No prerelease tag.
**NOT RUN:** owner's local build,
positive real Kerberos tickets/keytab
and confirmed GSS/TLS public-key proof,
OS authorization, external RDP client
or interactive desktop.

## Verified optional Linux real GSS probe compilation (2026-10-14)

The original Linux MIT GSS linked
`test_owned_preauth_session` executable
now COMPILES an opt-in
`security.gssapi-real-kerberos-tls-mechanism`
test using `gss_acquire_cred_from` with
an explicitly specified external FILE:
client cache and the production acceptor's
independent `FILE:` service keytab.
Only with
`RDP_SERVER_TEST_LINUX_GSSAPI=ON` AND
`RDP_SERVER_TEST_REAL_KERBEROS=ON`
on Linux does CMake register this CTest;
configuration fails for missing
`RDP_TEST_KRB5_SERVICE=TERMSRV/host@REALM`,
`RDP_TEST_KRB5_KEYTAB=FILE:/absolute/path`,
or `RDP_TEST_KRB5_CCACHE=FILE:/absolute/path`.
No daemon, KDC or test ticket is created
by the repository. Only an explicitly
authorized external isolated test
realm may provision these values.
The test uses real MIT GSS
`gss_init_sec_context` and the original
provider `gss_accept_sec_context`
on OpenSSL TLS for versions 5 and 6,
then a REAL GSS-confidential
binding-only TLS client/server proof,
and rejects a genuine context if a
new TLS frame reader sees a swapped
certificate on the same SSL object.
This is a diagnostic binding-only
provider test, not a real Microsoft
combined-final client/OS acceptance test.

**PASS:** implementation
`1f6740452f27332303ded71d4f5f23bb599b9726`,
[Actions 38678010820](https://github.com/k1moradi/RDP-server/actions/runs/38678010820):
normal Linux 72/72 and macOS/Windows
63/63 full CTests, BOTH Debug and Release,
installed SDK consumer/ZIP+SHA256/policy.
The optional code COMPILED with MIT GSSAPI
on Linux, but **NOT RUN:** the positive
case itself (no external keytab/cache
provisioned), controlled GSS positive
binding, OS session authorization,
Microsoft Windows App or actual desktop.
The existing unrelated Ubuntu Release
fixture warning remains nonfatal.

## Version-6 CredSSP failure DER and TLS delivery (2026-10-14; CI NOT RUN)

Register FOUR new behavior cases in
the ORIGINAL CTest registry
`tests/CMakeLists.txt`, reusing existing
`test_owned_credssp_tsrequest` and
`test_owned_preauth_session` sources.
`security.credssp-server-failure-wire`
compares independently hand-authored
15-byte DER oracles for signed
0xC000006D and 0xC00000BB, validates
existing TSRequest parser/framer
reads exactly errorCode and never
infers user authentication.
`security.credssp-server-failure-rejections`
rejects versions 0/2/3/4/5/7/255,
unknown statuses, invalid DER signed
integer width, and unrecognized
normal server reply fields.
`transport.credssp-tls-failure-reply-wire`
sends both actual v6 failure records
over the existing completed OpenSSL
server/client memory-BIO TLS and
validates the received exact ciphertext-
protected plaintext, error-only
field shape and writer terminal
state; it also checks a prior
negotiation response may be released
before a failure on the same TLS
certificate fingerprint.
`transport.credssp-tls-failure-reply-rejections`
asserts null/unfinished/client SSL,
v5 or malformed failure, pending
write conflict and SAME-SSL selected
X509 substitution all fail without
leaking another TLS record. Expected
full Linux **76**, macOS/Windows
**67** CTests per Debug and Release.
No separate test executable,
second sender or default GSS
auth context. **NOT RUN:** new CI,
opt-in genuine Kerberos, confirmed
confidential GSS/TLS binding,
real Microsoft client/OS session
authorization or interactive desktop.
