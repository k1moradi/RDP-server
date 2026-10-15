# CODEX_VALIDATION.md — validation ledger and agent contract

Read **[AGENTS.md](../AGENTS.md)** on every prompt together with
[VISION.md](VISION.md), the living TODO in
[docs/ROADMAP.md](ROADMAP.md), and the mandatory
[coding](coding_standards.md), [testing](testing_standards.md),
[compilation](compile.md) and [benchmark](benchmark.md) standards.

The detailed acceptance contracts live in `docs/testing_standards.md`.
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

## New transport stream intake milestone (pending CI)

This commit adds `PreauthConnectionStream` on top of the existing
X.224 parser and preauthentication session, with bounded first-packet
reassembly and exact consumed-byte accounting. The reused
`transport.preauth-session` CTest was extended with fragment,
coalescing, malformed-length, TLS-dispatch and terminal-close negatives.
**PASS:** [exact-head GitHub Actions run 38536987879](https://github.com/k1moradi/RDP-server/actions/runs/38536987879),
commit `988938a90f8adbae4e07714ac636af3eb0640011`, passed
Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy CTests.
This verifies the existing compiled preauth protocol suite and the
new bounded-fragment intake negative cases. The first **unimplemented**
boundary is a network listener coupled to a real TLS provider and
authenticated post-negotiation session. Real TLS/credential validation,
desktop admission and external RDP clients remain **NOT RUN**;
no production activation.

## X.224 write-completion ordering (pending exact-head CI)

In the existing `PreauthConnectionStream`, the connection reply
completion gate now precedes the preauthentication TLS transition.
Tests were added to the existing `transport.preauth-session` CTest:
premature TLS, write failure, duplicate reply completion, early
completion report and accepted one-shot completion. **PASS:** [Actions run 38537586258](https://github.com/k1moradi/RDP-server/actions/runs/38537586258)
completed successfully for exact commit
`18262c0e4bf9bc4ecec4c2d56b069d4fc723b1f1`, with
Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy jobs
green. This is a tested **offline preauthentication ordering rule**,
not a listening socket, real TLS handshake, CredSSP, user authentication
or OS session access; those categories remain NOT RUN.

## Verified bounded decrypted MCS/GCC intake (2026-10-14)

New reusable `PreauthConnectionStream::consumeDecryptedMcsConnectInitial`
uses one fixed buffer for the initial plaintext and the subsequent
decrypted MCS/GCC envelope. Existing `transport.preauth-session`
gains every-split, truncation, coalesced-packet, invalid header,
malformed BER, wrong-state and replay tests against production code.
**PASS:** [Actions run 38541509607](https://github.com/k1moradi/RDP-server/actions/runs/38541509607) at `49c6006d47476184f7448028cd332e377ec9bd0b` completed Linux/GCC, macOS/Clang, Windows/MSVC CMake builds and full CTests, plus documentation-policy. **NOT RUN:** owner's local `~/rdp-server/build/`, host networking, real TLS certificates, CredSSP/NLA, external RDP clients and OS admission. **Next:** authenticated TLS provider and MCS response lifecycle.

## Verified CI/CD protocol SDK automation (2026-10-14)

The unified `.github/workflows/ci.yml` now runs Debug and Release
builds/full CTests on Linux/GCC, macOS/Clang and Windows/MSVC, followed
by one staged install per runner, a nested downstream CMake consumer
configure/compile/CTest, CPack ZIP creation and artifact SHA-256
publication. A matching `protocol-vX.Y.Z` tag reachable from
`main` publishes a GitHub **prerelease** only after all platform
and documentation-policy jobs have succeeded. The new consumer tests
that the installed `RDPServer::protocol` target is usable.

**PASS:** [GitHub Actions run 38543429777](https://github.com/k1moradi/RDP-server/actions/runs/38543429777)
at exact commit `1aa025960288d40f476e85c5a9c5f97b06bebf20`
completed Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
For each OS the workflow configured/built/ran CTest in Debug,
reconfigured the **same** `build/` root for Release, ran Release
CTest, installed the SDK under `build/stage/`, compiled and ran the
downstream `tests/consumer` CTest under `build/consumer/`, and
successfully generated/uploaded CPack ZIP and SHA-256 manifests.
Artifacts: `protocol-package-ubuntu-latest`,
`protocol-package-macos-latest`, and
`protocol-package-windows-latest` (3 packages confirmed).

**SKIPPED / NOT RUN:** the gated GitHub release publishing job
(no `protocol-vX.Y.Z` tag was pushed), owner's local PC build,
live server/socket/service, real TLS/NLA, OS authorization, and
external RDP desktop acceptance. The next delivery gate is
a reviewed version tag to test the prerelease publish step;
the next functional gate is an authenticated native RDP server.

## Documentation relocation and CMake script-mode policy (2026-10-14)

Root docs were moved to `docs/` at commit
`e3e6a7576f530280a1095f8e15f058d7da07f52d`. All 47
internal documentation hyperlinks were rebased; root entrypoints
were preserved. **FAIL:** [Actions run 38544805819](https://github.com/k1moradi/RDP-server/actions/runs/38544805819)
failed `project.policy` on Ubuntu during Debug CTest because
`cmake -P` did not enable CMP0057 for `if(IN_LIST)`.
Ten native protocol suites passed on Ubuntu. Changed the root-layout
policy guard to `list(FIND)` in this follow-up implementation.
**PASS:** the corrected `cmake -P` root-layout guard at
`f68d1d417424823eed7856761ff95f0ebe1eabb2` passed
[GitHub Actions run 38544988535](https://github.com/k1moradi/RDP-server/actions/runs/38544988535)
on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
Each runner passed Debug and Release full CTests, staged SDK install,
downstream CMake consumer, CPack ZIP and SHA-256 artifact upload.
`project.policy` now checks required relocated docs and permits only
five canonical root-level Markdown entrypoints.
**NOT RUN:** owner-local `~/rdp-server/build/`, real clients, RDP
network listener, OS admission and service deployment.

## OpenSSL server TLS transition evidence (pending exact-head CI)

The previous `PreauthConnectionStream::onTlsHandshake(bool)` could
proceed on a caller-supplied synthetic signal. This transport API
now requires a fully handshaken server-side OpenSSL `SSL*` with a
selected certificate, cipher, and negotiated TLS 1.2+.
The existing `transport.preauth-session` CTest performs a real
in-memory OpenSSL client/server handshake and checks wrong role,
unfinished handshake, missing pointer, send-before-TLS and replay.

**NOT RUN** until exact-head CI verifies Linux/GCC, macOS/Clang,
Windows/MSVC, documentation-policy, Debug/Release, downstream
consumer and SDK packaging. **NOT RUN:** local owner checkout,
actual TCP listener, certificate enrollment, CredSSP/NLA,
OS identity authorization and external RDP clients.

## TLS boundary Windows compatibility failure (2026-10-14)

**Initial FAIL:** commit `a25b5186398e4a5619baea2998a61596fa7b2887`
[Actions run 38551275680](https://github.com/k1moradi/RDP-server/actions/runs/38551275680)
reported MSVC C2589/C2059 in
`src/server/transport/preauth_session.cpp` at `std::min`,
due to platform macro leakage from an OpenSSL header.
macOS and documentation-policy PASS. Corrected the public
include to `openssl/types.h`, included `ssl.h` only in
translation units using OpenSSL, and protected the two
`std::min` expressions with parenthesized function names.
**Next:** cross-platform Debug/Release full CTests, downstream
SDK consumer and ZIP packages on the corrected exact head.

## Verified OpenSSL TLS preauth stream gate (2026-10-14)

Initial security implementation
`a25b5186398e4a5619baea2998a61596fa7b2887` introduced a
completed-OpenSSL-server SSL check after X.224 reply completion and
a real memory-BIO client/server TLS handshake regression.
**First FAIL:** [Actions run 38551275680](https://github.com/k1moradi/RDP-server/actions/runs/38551275680)
on Windows/MSVC Compile Debug (Windows macro expanded in `std::min`).
Header isolation and parenthesized `std::min` at
`edfaf2e7ea684ab5adc77bf58441ff467288f818` corrected it.
**Exact-head PASS:** [Actions run 38551496274](https://github.com/k1moradi/RDP-server/actions/runs/38551496274)
passed Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release CTests, installed SDK consumer and ZIP upload.
This verifies that a completed in-memory **server-side OpenSSL
handshake** advances the offline stream when in order and rejects
null, client-role, unfinished, premature and repeated transitions.
It does **not** verify live socket TLS I/O, user authentication,
CredSSP/NLA, real external RDP client, OS admission or desktop.
The user-reported 11/11 local CTests preceded this TLS change;
local tests of the new exact commit remain **NOT RUN**.

## Verified OpenSSL application-record MCS intake (2026-10-14)

Added `PreauthConnectionStream::consumeMcsConnectInitialFromTls`
to read from the exact completed OpenSSL server connection and
feed its decrypted bytes into the existing bounded 8,192-byte
TPKT/X.224/MCS/GCC state machine. The existing
`transport.preauth-session` suite sends encrypted OpenSSL
application records through memory BIOs and tests every
Microsoft example split, coalescing, TLS EOF, early errors,
wrong/foreign SSL handles and malformed TPKT. The server
still does not listen on a socket, authorize users, emit MCS
responses or deliver a desktop.

**PASS:** exact code commit
`a226f15827e9da48ad7a91b7cfa53528c3498802`,
[GitHub Actions run 38557465241](https://github.com/k1moradi/RDP-server/actions/runs/38557465241)
completed Ubuntu/GCC, macOS/Clang, Windows/MSVC and
documentation-policy, the Debug/Release CTests, staged installation,
downstream SDK consumer, and three ZIP/checksum package uploads.
**NOT RUN:** user's local build on this new commit, external RDP
clients, nonblocking TCP socket, CredSSP/NLA identity/authorization,
MCS Connect-Response and desktop access.
**First remaining boundary:** real I/O adapter and OS-independent
authenticated RDP session policy.

## Verified CTest behavior reporting transparency (2026-10-14)

User reported a successful owner-local Debug CMake build and CTest at
`28b0d2b53949236eff4e483c2ca9706c25d93895`: **11/11 PASS**.
This is user-provided evidence for that local checkout, not evidence
for a later commit. The consolidated preauth executable still ran
new encrypted TLS tests but appeared as one CTest, lasting roughly
1.67 seconds in the provided output.

Now one binary accepts a documented behavior selector (or no argument
to run all groups), and the existing CMake test registry names
ten independent preauth behavior cases. Expected registered total:
20 (formerly 11), with unchanged protocol implementation and retained
assertions. **PASS:** implementation commit
`1e11327f2b74ff7e676fbb3bb7200491718a779f`,
[Actions run 38559221423](https://github.com/k1moradi/RDP-server/actions/runs/38559221423):
Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release CTests, installed downstream package consumer and
SDK ZIP/sha256 artifacts. Ubuntu's CTest logs explicitly show
**20/20 tests passed** for each Debug and Release run.
**NOT RUN:** owner's local CTest after this registration change,
external RDP clients, real TCP listener, CredSSP/NLA,
OS authorization or desktop acceptance.

## Verified partial X.224 output accounting (2026-10-14)

Removed the Boolean send-completion escape hatch from
`PreauthConnectionStream`. The existing owner tracks each
of the exact 19 negotiation-response bytes accepted by a
future nonblocking socket writer; it only allows SSL/TLS after
the last Confirm byte, or allows the Failure response to
drain before terminal close. The new named CTest validates
all split boundaries, bytewise writes, would-block, duplicate,
overrun, premature TLS, explicit failure and rejection output.
**PASS:** code commit `98f6fdc60d513d47a87a78fadf1aa6be387da28b`,
[GitHub Actions run 38561127854](https://github.com/k1moradi/RDP-server/actions/runs/38561127854)
passed Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release CTests, downstream SDK consumer and three packages.
Ubuntu's Debug and Release CTests each logged **21/21 PASS**.
**NOT RUN:** owner-local new build, active TCP listener, CredSSP/NLA,
MCS Connect-Response, external clients, OS/desktop authorization.
**First remaining boundary:** native nonblocking socket adapter
and authenticated RDP session lifecycle.

## Verified portable preauth TCP adapter (2026-10-14)

New `src/server/transport/nonblocking_tcp_adapter.{h,cpp}`
provides `NativeTcpIo` borrowed nonblocking Winsock/POSIX
socket calls, and `PreauthTcpAdapter` which drives the sole
existing `PreauthConnectionStream` state machine with exact
first-request prefix reads and bounded X.224 reply writes.
The existing native test binary registers two independent
behavior CTests for fragments/backpressure and rejected failure
output; expected CTest count increases from **21 to 23**.

**PASS:** implementation `dd3a806f97b13e6db18affd689c6321bfa009813`,
[Actions run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
completed Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
both Debug/Release full CTests, installed SDK downstream consumer,
and three platform package ZIPs/checksums. Ubuntu explicitly logged
**23/23 CTests PASS** for both build modes.
**NOT RUN:** owner's local build on this new exact code,
connected live native socket runtime, listening TCP RDP server,
live TLS network handshake, CredSSP/NLA, MCS responses,
real clients or independently authorized desktop admission.
**Next gate:** actual TLS-over-socket lifecycle with bounded
cancellation and then authenticated connection semantics.

## OpenSSL 4 fixture compile failure (2026-10-14)

**FAIL:** evidence-only commit `4578a4549b9a04638206264a0c5ac752ef5e844b`,
[run 38564061700](https://github.com/k1moradi/RDP-server/actions/runs/38564061700)
macOS Compile Debug, first failing call: the prior in-memory TLS
fixture assigned OpenSSL 4's `const X509_NAME*` return from
`X509_get_subject_name` to a mutable `X509_NAME*`. The
actual native TCP adapter implementation had independently passed
[run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
on all three OSes and 23/23 Debug/Release tests on Ubuntu.
The fix creates a temporary RAII `X509_NAME` and sets both
certificate subject and issuer using OpenSSL APIs; no
`const_cast` or reduced test assertion.
**PASS:** fixed implementation `5c4f3ad7273d17948327b7d351ff9840de2b0395`,
[Actions run 38564403002](https://github.com/k1moradi/RDP-server/actions/runs/38564403002):
Ubuntu/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
both Debug/Release **23 CTests**, downstream installed SDK consumer
and three platform ZIP/checksum artifacts.
**Caveat:** the successful macOS run found OpenSSL **3.6.4**;
post-fix compilation with 4.0.3 is **NOT RUN** and needs a
separate explicit CI check. **NOT RUN:** owner's local new tests,
actual native connected socket, real RDP clients, TLS-over-socket,
NLA, MCS Connect-Response and independently authorized OS desktop.
**Next functional boundary:** live socket TLS provider lifecycle
and authenticated session sequencing, then MCS response.

## Verified nonblocking OpenSSL handshake through sole connection owner (2026-10-14)

At parent `357add02b32eec5593b8a078d8ec56a4f7a6291e`,
the owner-reported local Linux Debug build and
`ctest --test-dir build -C Debug --output-on-failure`
completed **23/23 PASS**, including native TCP adapter tests.
This is supplied user-local evidence for that checkout, not
local execution of the new implementation.

This implementation adds `PreauthConnectionStream::advanceTlsHandshake`
and forwards it from `PreauthTcpAdapter::onTlsIoReady`.
It uses OpenSSL's server `SSL_do_handshake` once per event,
handles WANT_READ/WRITE without spinning, pins the original
borrowed SSL pointer, rejects wrong role, premature calls,
provider failure or replay, and advances only after the
existing completed-server-TLS evidence gate. Two new behavior
CTests use a real in-memory TLS BIO pair, one then decrypts
the Microsoft 416-byte MCS/GCC packet. Expected total:
**25 registered CTests**.

**PASS:** exact code commit
`fcd05f8e903a459ca85f13807bd35f7091f3fd70`,
[Actions run 38566584099](https://github.com/k1moradi/RDP-server/actions/runs/38566584099):
Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
succeeded. Ubuntu explicitly logged **25/25 PASS** in Debug and
Release; all three OSes passed the full CTests, staged install,
downstream consumer and CPack ZIP/checksums. No release tag,
server activation or machine changes took place.
**NOT RUN:** owner's updated local build, real connected TCP
TLS session, external RDP clients, CredSSP/NLA identity,
OS desktop admission and MCS server response.
**Next:** safe loopback native TLS I/O/regression; full secure
connection and authenticated RDP session remain open.


## Native loopback OpenSSL/TCP integration (pending exact-head CI)

User-provided owner-local Linux output for `91e066b8214dd04299e94ccfd8167c940148e2a4`:
reused `~/rdp-server/build/`, Debug C++23 compilation and
`ctest --test-dir build -C Debug --output-on-failure` were
**PASS 25/25**. This local evidence predates this change.

The implementation adds a borrowed nonblocking OpenSSL BIO atop
`TcpNonblockingIo`, then tests real short-lived IPv4 loopback
socket exchange of X.224 CR/Confirm, server-side TLS handshake
and encrypted 416-byte MCS/GCC frame. Native EOF and
NEG_FAILURE delivery are separate negative test behavior.
Expected CTest registration **27**. OpenSSL BIO callbacks
follow its documented retry/ownership semantics; no socket
handle narrowing, persistent listener or user authorization.

**NOT RUN:** this commit's Linux/GCC, macOS/Clang and Windows/MSVC
Debug/Release hosted CTests, SDK consumer/package and
documentation-policy until the exact-head Actions run completes.
**NOT RUN:** user's local update, external RDP client handshake,
certificate enrollment/validation, CredSSP/NLA, licensing,
MCS Connect-Response, approved OS identity and desktop.
First remaining server boundary: independent authenticated
session policy followed by standards-compliant MCS response.

## Loopback TCP readiness timing regression (2026-10-14)

**FAIL:** `c53a591c8d5b6dbb4cd63f742bddb2c3eeb2ede8`,
[CI 38578878083](https://github.com/k1moradi/RDP-server/actions/runs/38578878083):
macOS Debug `transport.tcp-native-loopback-tls` and
`transport.tcp-native-loopback-close` expected TCP recv/readable
FIN synchronously after client send/close. Actual native nonblocking
sockets may return WouldBlock first. Linux and Windows passed
all 27 CTests, packaging and documentation-policy passed.
Correct the **test event driver** to retry only in bounded
short sleeps with unchanged exact packet, EOF and protocol
acceptance assertions; no production behavior is altered.
**NOT RUN:** post-fix CI on the corrected commit, new
owner-local tests and any external RDP client or desktop.

## Verified nonblocking native OpenSSL/TCP loopback bridge (2026-10-14)

**First FAIL:** code commit `c53a591c8d5b6dbb4cd63f742bddb2c3eeb2ede8`,
[run 38578878083](https://github.com/k1moradi/RDP-server/actions/runs/38578878083)
passed Linux/GCC, Windows/MSVC and documentation-policy but failed
two macOS Debug native-loopback CTests. The test driver incorrectly
assumed a nonblocking recv or FIN would be visible immediately
after its peer's send/close. There was no proved production transport
bug. Fixed only the test harness: bounded waits for the expected
readability and TCP EOF outcomes, preserving exact-packet and
fail-closed assertions.

**PASS:** corrected exact code commit
`7ce64737ccef439af2f0cfd383208181cc0e9513`,
[Actions run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
completed Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
both Debug/Release full CTests, staged SDK install, downstream consumer,
and three ZIP/checksum package artifacts. Ubuntu logs explicitly
show **27/27 CTests PASS** in both configurations, including
`transport.tcp-native-loopback-tls` and
`transport.tcp-native-loopback-close`.

The verified boundary is real **local-only connected TCP** X.224
negotiation, an OpenSSL server handshake across those native sockets
and decrypted MCS/GCC example intake. The test's ephemeral
127.0.0.1 listener was closed before TLS; it did not activate any
persistent service. **NOT RUN:** owner's build after this new change,
external RDP client admission, production certificate enrollment/trust,
CredSSP/NLA identity, MCS Connect-Response, licensing,
OS desktop authorization or graphics.
**Next:** authenticated RDP session sequencing and real server-side
MCS response, without confusing local transport security with OS
authorization.

## MCS domain parameter merge (2026-10-14; pending exact-head CI)

User-provided owner-local Linux Debug build and CTest on
`03d72824e87c5f6e608e1d27ff2711bb8a88b1e0`:
**PASS 27/27** with the sole persistent
`~/rdp-server/build/`. This evidence predates the new change.

The implementation extends the maintained MCS Connect-Initial
parser with Microsoft MS-RDPBCGR 3.3.5.3.3/T.125 domain
parameter merge. It returns a value only, never admits an OS
session, allocates channels or sends a response. The existing
preauth owner now rejects a BER-valid MCS Connect-Initial if
its requested domain cannot negotiate version 2 or any
required domain minimum. Four existing MCS test behavior
groups are reported separately, with two new groups for
negotiation and malformed values; expected **32 CTests**.

**NOT RUN:** CI on exact new implementation SHA,
owner-local updated build, authenticated CredSSP/NLA/OS
identity, MCS Connect-Response, external Microsoft clients
and desktop access. First next wire boundary: bounded
standards-compliant server MCS Connect-Response and GCC
Conference Create Response, gated by secure authorization.

## Offline MCS Connect-Response encoder (2026-10-14; CI pending)

**Owner-local evidence:** at
`865c56c548526f4514207a4af1b192f3b3637c9a`,
the user's reused `~/rdp-server/build/` Debug compile and
`ctest --test-dir build -C Debug --output-on-failure`
completed **32/32 PASS**. The same implementation completed
cross-platform Debug/Release and SDK gates in
[CI 38582674975](https://github.com/k1moradi/RDP-server/actions/runs/38582674975):
Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
all PASS. That is prior-code evidence, not evidence for this encoder.

**New implementation:** a bounded offline encoder of the
MS-RDPBCGR 2.2.1.4 TPKT/X.224, BER MCS Connect-Response and
PER GCC Conference Create Response containing `McDn`,
`SC_CORE`, `SC_NET` and Enhanced TLS `SC_SECURITY`. It
requires a checked merged domain and GCC client data plus
caller-provided nonduplicated channel IDs. Tests include
a full independently specified 108-byte example and
rejection paths. Expected CTest registration **34**.
**NOT RUN:** exact-head cross-platform Debug/Release CI,
owner-local post-change build, actual output to a TLS
socket, CredSSP/NLA and independently authorized OS session,
MCS Erect/Attach/Join lifecycle, external Microsoft clients
or desktop acceptance. This is not an authenticated server.

## Pure MCS Channel Connection Request decoding (2026-10-14; pending CI)

**Owner-local baseline:** at `ddfc2d372285c397c52dca0197d30bf1c61c338e`,
the owner's Linux Debug command reused `~/rdp-server/build/`
and confirmed **34/34 CTests PASS**, including the offline
MCS response wire/negative tests. The earlier implementation
`e25cd3a05f46b7eaa2a259eb2da8ddb3b7459a87` had Linux,
Windows and documentation-policy PASS in
[CI 38586253181](https://github.com/k1moradi/RDP-server/actions/runs/38586253181).
These are prior-code results, not proof of this change.

**New scope:** pure, bounded T.125 Channel Connection request
parser for ErectDomain/AttachUser/ChannelJoin. Reuse existing
TPKT/X.224 parser and MCS fixture executable; add three CTests
from Microsoft wire examples with truncated/invalid negative
cases; expected **37 registered CTests**. No MCS channel state,
live response emission, OS admission, independent identity
or credential acceptance was implemented.
**PASS:** corrected implementation
`6effdb76229e2514511ebe5dd8cb404841403b1b`
in [Actions run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653):
Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
Debug/Release **37 registered CTests**, installed SDK consumer
and all three platform packages/checksums.
**NOT RUN:** owner-local corrected tests, external clients,
CredSSP/NLA or authenticated OS desktop.
**Next:** authoritative, independent authentication gate
before server-owned MCS channel/join replies.

## First MCS Erect-domain fixture failure (2026-10-14)

**FAIL:** initial implementation
`d5bc7d3b03906890da483dd1a480677a4fbaf73b`,
[Actions run 38588334504](https://github.com/k1moradi/RDP-server/actions/runs/38588334504),
Ubuntu Debug `transport.mcs-erect-request` asserted a valid
expanded Erect-domain example. Its subInterval PER length
determinant was incorrectly 4 for three following octets,
so the production decoder correctly rejected it.
Other 36 CTests PASS on Ubuntu. Fix only the test vector to
encode length 3 for 0x010203; no production code changes,
no weakened input bounds or removed assertions.
**PASS:** corrected code
`6effdb76229e2514511ebe5dd8cb404841403b1b`,
[CI run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653):
Linux, macOS, Windows and documentation-policy PASS with
Debug/Release **37/37 CTests** on Ubuntu and full tests on
other platforms, staged installation, downstream consumer and
three SDK ZIPs/checksums. No code path grants user access
or sends an MCS channel response. **NOT RUN:** owner-local
new CTests, external Microsoft clients, credential/session
authorization and graphics.

## Verified offline T.125 Attach/Channel response wire encoders (2026-10-14)

**User-provided prior evidence:** `3135d66e557ecc8144fba02a8a69b5054b62ede9`
at the single `~/rdp-server/build/` Debug configuration
compiled and passed **37/37 CTests**. Hosted CI on that
same SHA [38588943436](https://github.com/k1moradi/RDP-server/actions/runs/38588943436)
also passed Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release,
SDK consumer/package and documentation policy. Those
results do not verify the present changes.

**New implementation:** add offline fixed-array T.125
`rt-successful` Attach User Confirm and Channel Join
Confirm encoders beside the existing request decoders.
Test exact Microsoft 11- and 15-byte positive example
packets and negative allocation/UserId checks in two
additional CTest cases (expected **39**). The returned
buffer is not an authenticated session or permission to
transmit. **PASS:** exact implementation
`4eb3bff4f9fc15cb72da1b8e994ec89e7e9a96db`,
[Actions run 38590263498](https://github.com/k1moradi/RDP-server/actions/runs/38590263498):
Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
full Debug/Release CTests (Ubuntu **39/39 PASS** in each),
staged installed SDK downstream consumer and all three
platform package ZIP/checksum uploads. Prerelease publishing
was SKIPPED; no release tag.
**NOT RUN:** owner's local rebuild at this commit,
CredSSP/NLA identity verification, independently authorized
OS session, live encrypted MCS responses, external client
acceptance, licensing/share activation or desktop.
**Next:** real CredSSP/NLA and OS authorization in the
single existing connection owner, then enforce MCS reply
ordering and live transport admission.

## First-party CredSSP TSRequest incremental framing (2026-10-14; CI NOT RUN)

**Prior evidence:** main commit
`7ffe0609fe25b15e07f1c49755a4b37b3b7a41b9`
passed Linux/GCC, macOS/Clang, Windows/MSVC,
documentation-policy, Debug/Release 39 CTests,
downstream SDK consumer and all three packages in
[CI 38590674716](https://github.com/k1moradi/RDP-server/actions/runs/38590674716).
The owner reports all tests passed on that prior code,
without attaching a new CTest log. Not verification of this
implementation.

**New implementation:** bounded `TsRequestFrameReader` in
the existing `credssp_tsrequest` translation unit; exact
DER frame intake across TLS plaintext fragments with
canonical length checks, complete-frame non-replay,
borrowed frame handoff and `OPENSSL_cleanse` on release,
close or destructor. Tests reuse the existing CredSSP
executable; three new named behaviors plus separate
registration of five existing groups. Expected CTest total
**46**. **PASS:** exact implementation
`c7f0463a3e11c8bd9fb6e8dfb404c3f1057d40cd`,
[Actions run 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562):
Linux/GCC, macOS/Clang, Windows/MSVC and
documentation-policy, both Debug/Release full CTests,
installed downstream SDK consumer and three ZIP/SHA-256
packages. Ubuntu explicitly logged **46/46 CTests PASS**
in both configurations. No release tag or service activation.
**NOT RUN:** owner's local updated build, real GSS/SPNEGO
handshake, TLS public-key binding, credential verification,
OS session authorization, NLA security selection, MCS
response emission, external client and desktop access.
**Next:** a trusted authenticated CredSSP/SPNEGO and OS
authorization provider within the sole preauth owner.

## Verified offline CredSSP server TSRequest reply serializer (2026-10-14)

**Prior verified head:** `f3f2d727334a254f7970c5eefe3c91a25d82c41e`,
[CI 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562)
passed Linux/GCC, macOS/Clang, Windows/MSVC, documentation policy,
46/46 Debug/Release CTests and SDK consumer/package gates for
the prior TSRequest framing implementation.

**New increment:** one `encodeCredSspServerTsRequest` entry point
in existing portable CredSSP module, accepting an opaque
GSS provider output for one of two distinct MS-CSSP server
response types, versions 5/6 only. It returns a complete
canonical bounded DER frame or no output; it owns no
authentication authority. The same CredSSP test executable
adds exact-wire, long-length, framing, empty/oversize,
unsupported-version/field regressions. Expected 48 named
CTests. **PASS:** exact code/test implementation `46e77ed65afdd9526ee1c63d39724668670cf047`,
[CI run 38596955778](https://github.com/k1moradi/RDP-server/actions/runs/38596955778) passed documentation-policy
and Linux/GCC, macOS/Clang, Windows/MSVC full Debug/Release
**48/48 CTests** each. SDK install, consumer configure/link/
execute, ZIP/checksum and artifact upload passed for all three
platforms; prerelease publication was SKIPPED because this
is not a protocol version tag. CI commands included:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build --build-config Debug --output-on-failure`,
then reconfiguration with `-DCMAKE_BUILD_TYPE=Release`,
the same build root and corresponding Release build/CTest.
An unrelated Ubuntu Release preauthentication test source
logged a pre-existing `-Wstringop-overflow` warning at
`tests/test_owned_preauth_session.cpp:582`; it did not
fail the compilation or tests.
**NOT RUN:** owner-local build, genuine SPNEGO/GSS,
TLS key binding, OS account authorization or Microsoft
desktop connection. **Next:** a verified authenticated
security provider and independent OS-authorized single
session owner; do not send positive responses from offline
serialization.

## Verified Linux GSSAPI provider compile and framed DER handoff (2026-10-14)

**Previous baseline:** `35698b939bb2d26a66ca80ba237a55dc70e2da54`
passed 48/48 CTests on three platforms in
[CI 38597459891](https://github.com/k1moradi/RDP-server/actions/runs/38597459891).

**Implementation:** `36989cebcc6a69b51d1c3f3d5d1f2660417a9865`
adds the Linux-only real MIT GSSAPI build/test target
and synchronous completed v5/v6 CredSSP DER frame handoff,
with terminal rejection and wipe on all invalid/unsupported
steps. No credentials, positive Kerberos handshake, or
admission authority is introduced.
**PASS:** [CI 38603782133](https://github.com/k1moradi/RDP-server/actions/runs/38603782133)
with Linux/GCC Debug/Release **50/50** CTests, macOS/Clang
and Windows/MSVC Debug/Release **48/48** each; verified
both native GSSAPI named suites on Linux, documentation
co-change, staged SDK install, downstream consumer and
all three ZIP/SHA-256 uploads. In the one CI `build/`:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
-DRDP_SERVER_TEST_LINUX_GSSAPI=ON` (Linux; OFF elsewhere),
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build --build-config Debug --output-on-failure`;
reconfigure the same root for Release, build and retest.
Ubuntu's unrelated, previously reported
`tests/test_owned_preauth_session.cpp:582`
Release compiler warning remains nonfatal.
**NOT RUN:** owner-local updated build, configured real
Kerberos keytab/tickets, positive GSS mutual/authenticated
exchange, SSL certificate binding, independent OS user
authorization or Microsoft desktop.
**Next:** a controlled positive GSS/TLS certificate-bound
provider integration, with independently verified OS
session admission kept closed until explicit evidence.

## Verified native TLS -> CredSSP DER intake (2026-10-14)

**Prior baseline:** `c753b7d205647374c14e24be52b9f9f22fa8efcc`,
[CI 38604244975](https://github.com/k1moradi/RDP-server/actions/runs/38604244975),
Linux/GCC 50/50, macOS/Clang and Windows/MSVC
48/48 in Debug/Release, installed SDK, all packages
and policy PASS.

**New code and tests:** exact implementation
`d2885363502e34e52c71c41342902908b781fd58`.
Changed `src/server/security/credssp_tsrequest.{h,cpp}`,
`tests/test_owned_preauth_session.cpp`,
`tests/CMakeLists.txt`, plus same-commit roadmap,
architecture and standards. Add single bounded
`SSL_read_ex` from established server SSL directly
to the owned DER TSRequest framer; pin TLS identity,
separate `Progress` from WANT_READ/WANT_WRITE, never
read a coalesced second frame before release, reject
mixed plaintext/TLS sources and TLS EOF and wipe buffers.
Add three dedicated positive/negative real in-memory
OpenSSL TLS CTests (not simply reusing prior assertions).
**PASS:** [Actions run 38607049062](https://github.com/k1moradi/RDP-server/actions/runs/38607049062),
completed all four jobs successfully: Linux/GCC
**53/53** Debug and Release, macOS/Clang and Windows/MSVC
**51/51** each in Debug and Release. Each new
`transport.credssp-tls-fragments`,
`transport.credssp-tls-coalesced` and
`transport.credssp-tls-rejections` passed on all
three systems. SDK installed downstream consumer,
per-OS ZIP/SHA-256 uploads and policy PASS. Commands
within the sole CI `build/` root:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON -DRDP_SERVER_TEST_LINUX_GSSAPI=ON`
(Linux, OFF for macOS/Windows), `cmake --build build
--config Debug --parallel 2`, `ctest --test-dir build
--build-config Debug --output-on-failure`,
then reconfigure same root for Release, build,
CTest, install/consumer, CPack and SHA-256/upload.
The earlier Ubuntu Release preauth test fixture
warning `-Wstringop-overflow` remains nonfatal
(line shifted from 582 to 584).
**NOT RUN:** owner-local updated build, real
CredSSP/GSS provider ticket/keytab, TLS public-key
binding, independent OS identity authority, or
external Microsoft RDP desktop acceptance.
**Next:** authenticated real GSS/TLS binding and
OS session policy, not a synthetic admission.

## Verified GSS TLS provenance and version pinning (2026-10-14)

**Previous green head:** `82193719abd23e87abfcaa6a0932a11ca499d15a`,
[CI 38607454966](https://github.com/k1moradi/RDP-server/actions/runs/38607454966):
Linux 53/53 and macOS/Windows 51/51 Debug/Release
CTests plus portable SDK consumer, package uploads
and documentation gate.

**New implementation:** `6e11b25224e1a5e6c3f45778436afc3950a3e866` changes
`src/server/security/credssp_tsrequest.h`,
`src/server/security/gssapi_spnego_acceptor.{h,cpp}`,
`src/server/security/gssapi_credssp_binding.cpp`,
`tests/test_owned_preauth_session.cpp` and
`tests/CMakeLists.txt`, together with authoritative
roadmap, architecture, coding/testing standards and
this ledger. Carries real server-TLS completed-frame
provenance from the single framer to the actual Linux
MIT GSSAPI acceptor, pins SSL and version 5/6
across SPNEGO tokens, and refuses protected GSS
pubKeyAuth without that same SSL/version.
**PASS:** [CI 38609620612](https://github.com/k1moradi/RDP-server/actions/runs/38609620612)
completed SUCCESS: Linux/GCC **55/55**, macOS/Clang
and Windows/MSVC **52/52** CTests in both Debug
and Release, including both new `transport.credssp-tls-provenance`
and Linux-only `security.gssapi-tls-ownership`.
All 4 jobs passed: 3 platforms and documentation-policy;
staged installed SDK consumer, ZIP and SHA-256 artifact
uploads each succeeded, prerelease publisher SKIPPED
(no tag). CI commands:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`
with `-DRDP_SERVER_TEST_LINUX_GSSAPI=ON` on Linux
(OFF for macOS/Windows), `cmake --build build --config
Debug --parallel 2`, `ctest --test-dir build
--build-config Debug --output-on-failure`, then
reconfigure and re-use the same `build/` root in
Release and rerun builds, CTests, SDK installation,
consumer, CPack packaging and checksum upload.
A pre-existing nonfatal Ubuntu Release test compiler
warning at `tests/test_owned_preauth_session.cpp:587`
remains open. **NOT RUN:** owner's local updated
build, real Kerberos ticket/keytab and successful
GSS session, TLS public-key binding, OS account
authorization, Windows App/FreeRDP or desktop.
**Next:** authenticated positive GSS/TLS transcript,
combined final client negoTokens/pubKeyAuth
interoperability and independently verified OS
identity before a live MCS or desktop.

## Verified combined final SPNEGO + TLS pubKeyAuth (2026-10-14)

**Prior main:** `5a17ed4bd38a4af818f2541c2d1f858f5765d92c`,
[CI 38610037109](https://github.com/k1moradi/RDP-server/actions/runs/38610037109)
passed Linux/GCC 55/55 and macOS/Windows 52/52
Debug/Release CTests, policy, installed SDK consumers
and three ZIP/checksum packages.

**Exact implementation:**
`ad848646391eb7f2dce5c8e2a6238212e7f4e5ae`.
Changed `src/server/security/credssp_tsrequest.h`,
`src/server/security/gssapi_spnego_acceptor.h`,
`src/server/security/gssapi_credssp_binding.cpp`,
`tests/test_owned_credssp_tsrequest.cpp`,
`tests/test_owned_preauth_session.cpp`,
`tests/CMakeLists.txt`, plus canonical roadmap,
architecture, coding/testing standards and validation.
The MS-CSSP 3.1.5 combined final v5/v6 client request
now requires exactly one GSS token, encrypted pubKeyAuth
and a 32-byte nonce in one TLS-derived frame. A
continuing and pinned SSL/GSS context must finish
GSS security verification and unwrap/compare the
client binding, wrap the server binding, and wipe/release
the same frame. Outstanding GSS reply tokens, bad
field shapes, wrong order or failed provider remain
terminal, never yielding desktop authorization.

**PASS:** [Actions run 38612269453](https://github.com/k1moradi/RDP-server/actions/runs/38612269453),
all four jobs SUCCESS, with Linux/GCC Debug and
Release **58/58**, macOS/Clang and Windows/MSVC Debug
and Release **54/54** CTests. Linux's real GSSAPI
`security.gssapi-final-combined-denials` and
portable `security.credssp-final-negotiation-binding`
and `security.credssp-final-binding-rejections`
passed in BOTH configurations. The staged SDK
installation, downstream consumer configure/link/
execute, CPack ZIP/SHA-256 and artifact upload each
passed on all three OSes; documentation policy passed.
In CI's sole checkout-local `build/`: 
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON` (Linux additionally
`-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`, OFF elsewhere),
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build --build-config Debug
--output-on-failure`, same-root Release reconfigure,
build and CTest, SDK/consumer/CPack/upload.
Existing Linux Release `-Wstringop-overflow` warning
at `tests/test_owned_preauth_session.cpp:587`
persists but is nonfatal.
**NOT RUN:** owner's local new checkout build,
real keytab/tickets, positive Kerberos mechanism
and TLS binding verification, independently authorized
OS identity, external Windows App/FreeRDP or desktop.
**Next:** verify real successful GSS/Kerberos + active
TLS pubKeyAuth and independent OS policy before
enabling live MCS domain response emission.

## Verified nonblocking CredSSP server TLS reply transport (2026-10-14)

**Previous green head:** `a3f841a572aa861cbaa1ff890b228598e612fccc`,
[CI 38612678888](https://github.com/k1moradi/RDP-server/actions/runs/38612678888):
Linux/GCC 58/58 and macOS/Windows 54/54
full Debug/Release CTests and all SDK/policy/
packaging gates PASS.

**Initial code implementation:**
`915cd2bfac59d7e775b458b7deed3d94db17ad93`.
Added one bounded `TsRequestTlsReplyWriter`
to `src/server/security/credssp_tsrequest.{h,cpp}`,
alongside 3 new behavior-named CTests in
`tests/test_owned_preauth_session.cpp`,
`tests/CMakeLists.txt`, with roadmap,
architecture, coding/testing standards and
this validation ledger co-changed.
Single TLS-bound owned canonical server DER
response, stable buffer across `SSL_write_ex`
WANT_READ/WANT_WRITE, no duplicate frames,
and explicit wipe-on-release/fail/close.

**Initial CI FAIL:** [CI 38614500856](https://github.com/k1moradi/RDP-server/actions/runs/38614500856).
The test fixture's attempt to resize an already
connected BIO pair with `BIO_set_write_buf_size`
after the TLS handshake failed on macOS Debug.
No claim of passing backpressure was made.
**Corrective commit:**
`afa7d737b4ee32c0f0e72bbedd32e6cb9066afd6`,
constructs the same OpenSSL memory-BIO pair
with optional 2048-byte server write capacity
BEFORE real TLS handshake and keeps all test
assertions.

**PASS:** [CI 38614808824](https://github.com/k1moradi/RDP-server/actions/runs/38614808824)
completed successfully for all four jobs:
Linux/GCC **61/61** and macOS/Clang,
Windows/MSVC **57/57** CTests in BOTH Debug
and Release, including ALL three new
`transport.credssp-tls-reply-wire`,
`transport.credssp-tls-reply-backpressure`
and `transport.credssp-tls-reply-rejections`.
The Linux-only real GSS provider rejection
cases remain green. Installed SDK consumer,
three ZIP/SHA256 artifact uploads and
documentation policy passed. Commands within
the sole CI `build/` root:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON` (Linux: 
`-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`, OFF
for macOS/Windows), `cmake --build build
--config Debug --parallel 2`,
`ctest --test-dir build --build-config Debug
--output-on-failure`; reconfigure same root
in Release, build/CTest, staged install,
downstream CMake consumer, CPack ZIP,
SHA-256 digest and artifact upload.
A preexisting nonfatal Ubuntu Release warning
`-Wstringop-overflow` remains at
`tests/test_owned_preauth_session.cpp:589`.
Prerelease publication SKIPPED (no version tag).
**NOT RUN:** owner-local updated build,
valid GSS Kerberos keytab/tickets and a real
successful provider-selected TLS pubKeyAuth
exchange, independently authorized OS account,
Windows App/FreeRDP or desktop.
**Next:** controlled real GSS/TLS positive
authentication and independent OS session
policy BEFORE any real MCS channel/domain
reply or remote desktop admission.

## Verified Linux MIT GSSAPI -> bounded TLS replies (2026-10-14)

**Prior exact main:** `195603ce733724b8940523f11b59d8c328d14e66`,
[CI 38615240623](https://github.com/k1moradi/RDP-server/actions/runs/38615240623):
Linux 61/61 and macOS/Windows 57/57
Debug+Release CTests, documentation,
SDK consumer and packages PASS.

**Implementation:**
`27e8342aee0e475c3b0854330678e7c7596fc912`
changes
`src/server/security/gssapi_spnego_acceptor.{h,cpp}`,
`src/server/security/gssapi_credssp_binding.cpp`,
`tests/test_owned_preauth_session.cpp`,
`tests/CMakeLists.txt` and the existing
roadmap, architecture, coding/testing
standards and this verification ledger.
Adds two direct provider->writer methods:
`acceptFramedNegoAndQueueReply` requires
a continuing real MIT GSS context and
its nonempty provider output;
`processFinalFramedNegoAndQueueBindingReply`
requires successful combined-final
GSS context verification, confidential
client binding, matching active server
TLS certificate, and real GSS-wrapped
server binding. Both require writer
idle, same SSL/version, wipe transient
tokens and close reader/writer/provider
atomically on error. They queue DER
but do NOT call `SSL_write_ex`,
admit identity, send an MCS reply
or install a live server.

**PASS:** [Actions 38617602493](https://github.com/k1moradi/RDP-server/actions/runs/38617602493)
completed SUCCESS with all 4 jobs:
Linux/GCC Debug and Release **64/64**,
macOS/Clang and Windows/MSVC
Debug and Release **57/57** CTests.
All 3 new Linux-only named tests
`security.gssapi-negotiation-reply-gates`,
`security.gssapi-binding-reply-gates`,
`security.gssapi-reply-order-denials`
passed. SDK installed consumer, CPack
ZIP/SHA-256 manifests and all three
artifact uploads, documentation-policy
PASSED. CI uses each checkout-local
single `build/`:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON -DRDP_SERVER_TEST_LINUX_GSSAPI=ON`
(Linux; OFF on macOS/Windows);
`cmake --build build --config Debug --parallel 2`;
`ctest --test-dir build --build-config Debug
--output-on-failure`; same-root Release
reconfigure/build/CTest, staged SDK
installation, downstream consumer,
CPack and SHA-256 package upload.
Existing Ubuntu Release
`tests/test_owned_preauth_session.cpp:589`
`-Wstringop-overflow` warning
remains nonfatal. Prerelease skipped
(no tag).
**NOT RUN:** user's own persistent
local `~/rdp-server/build`, successful
positive Kerberos service keytab,
client tickets, mutually verified
GSS/TLS certificate-bound proof,
independent OS session admission,
Windows App/FreeRDP or desktop.
**Next:** controlled opt-in positive
GSS Kerberos / selected TLS proof
then independently audited OS
authorization before live RDP
channel, graphics or desktop.

## Verified selected server TLS certificate pinning (2026-10-14)

**Previous green head:** `1bfbc3452078ed1a4676551953e325366981e587`,
[CI 38618001913](https://github.com/k1moradi/RDP-server/actions/runs/38618001913)
Linux/GCC 64/64, macOS/Windows 57/57
CTests in both Debug and Release, all SDK/
policy and packaging gates PASS.

**Initial implementation:**
`d0583c92eb6b6a3517d5e96ea5fd8adc07ee413d`.
`src/server/security/credssp_tls_certificate.{h,cpp}`
adds a SHA-256 fingerprint of the selected
established server X.509 certificate and
centralizes TLS >=1.2 server-role/cipher/
certificate checks for binding computations.
`src/server/security/credssp_tsrequest.{h,cpp}`
pins the selected certificate fingerprint
alongside the original SSL handle from the
first completed server TLS read and rechecks
it before subsequent TLS reads, even after
`releaseFrame`, and again before releasing
completed frame SSL provenance to GSSAPI.
Any changed selected certificate on the
SAME SSL handle is terminal; close wipes
frame and fingerprint. One owner, no
additional connection or GSS controller.
`tests/test_owned_preauth_session.cpp`
adds three independent, behavior-named
CTests, registered in `tests/CMakeLists.txt`,
with real TLS handshakes, live certificate
hash oracles and same-SSL selected-certificate
replacement after complete or partial frame.
Roadmap, architecture, coding/testing
standards and this ledger co-changed.

**Initial CI FAIL:**
[Actions 38619291326](https://github.com/k1moradi/RDP-server/actions/runs/38619291326)
Linux/GCC Debug test compilation failed
on `SSL_get_certificate` returning
`const X509*` versus
`SSL_use_certificate` expecting `X509*`.
The production objects compiled but
tests had NOT passed.
**Corrected commit:**
`340ce518d0e84ea94a4d24c295f8fa88e74ccf6d`:
use `X509_dup` into the existing mutable
RAII `CertificatePointer` on both full-frame
and partial-frame certificate-swap tests;
assert matching selected live fingerprints.
No assertions disabled or skipped.

**PASS:** [Actions 38619544190](https://github.com/k1moradi/RDP-server/actions/runs/38619544190)
all FOUR required jobs SUCCESS:
Linux/GCC **67/67**, macOS/Clang and
Windows/MSVC **60/60** CTests EACH in
Debug AND Release. All THREE new tests
`security.credssp-active-tls-binding-positive`,
`security.credssp-active-tls-binding-rejections`,
`transport.credssp-tls-certificate-pinning`
PASS on all systems. Installed SDK
downstream consumer configure/link/execute,
CPack ZIP/SHA-256, all three artifact uploads,
documentation policy PASS. CI used one
checkout-local `build/` per job:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON` (+ Linux-only
`-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`),
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build --build-config Debug
--output-on-failure`; then reconfigure
same root Release/build/CTest, stage install,
SDK downstream consumer, CPack and checksum.
Existing nonfatal Ubuntu Release compiler
warning in test fixture remains. No release
tag/prerelease publication.
**NOT RUN:** owner's local updated build,
actual successful Kerberos/GSS keytab
and client tickets, authenticated real
GSS unwrap/wrap of the pinned TLS
certificate hash, separately authorized
OS account or live Microsoft/FreeRDP
client and desktop.
**Next:** opt-in controlled real positive
GSS/Kerberos + TLS certificate binding,
then independent OS policy before
live MCS/session and desktop admission.

## Verified Linux GSS binding-only TLS-frame provenance (2026-10-14)

**Previous exact green main:**
`2d08e9662ed1a597a81b9e3424770cdc5fe0b335`,
[CI 38619989509](https://github.com/k1moradi/RDP-server/actions/runs/38619989509)
Linux 67/67 and macOS/Windows 60/60 CTests,
Debug+Release and SDK/policy/packages PASS.

**Implementation:**
`340b25d2352314003053ec19d467b75d578c9dbf`
changes `src/server/security/gssapi_spnego_acceptor.h`
and `src/server/security/gssapi_credssp_binding.cpp`.
The historical direct
`processProtectedBinding(SSL*, rawDer)`
has NO positive path because caller DER
lacks SSL/TLS record provenance. New
`processFramedProtectedBinding` borrows the
completed strict binding-only DER from the
single `TsRequestFrameReader`, checks its
verified original SSL and selected X.509
certificate/version, requires actual
GSS `MechanismVerified` before confidential
GSS unwrap/client nonce hash comparison
and GSS wrap, then releases/wipes the
original frame. The new
`processFramedProtectedBindingAndQueueReply`
shares the existing guarded queue
with the strict combined-final method,
never overwrites pending writer output
and always cleanses protected GSS tokens
or closes all three owners on failure.
Two independent Linux real OpenSSL
memory-BIO CTests added in the existing
`tests/test_owned_preauth_session.cpp`
and `tests/CMakeLists.txt`; relevant
roadmap, architecture, coding/testing
standards and this ledger co-changed.
No standalone executable, default service
or second GSS state machine was added.

**PASS:** [Actions 38623829568](https://github.com/k1moradi/RDP-server/actions/runs/38623829568)
all four required jobs SUCCESS:
Linux/GCC full **69/69** CTests in Debug
and Release, including both new
`security.gssapi-framed-binding-only-denials`
and `security.gssapi-framed-binding-reply-order`;
macOS/Clang and Windows/MSVC each
**60/60** CTests, BOTH Debug and Release.
Three SDK installed downstream consumers,
CPack ZIP/SHA-256 checksum artifacts
and all package uploads and documentation
policy PASS. Per-job CI used only
checkout-local `build/`: configure Debug
with Linux `-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`
(portable OFF), compile Debug and
`ctest --test-dir build --build-config Debug
--output-on-failure`, reconfigure the
same root for Release, compile/CTest,
staged install/consumer/CPack/sha256/upload.
Preexisting nonfatal Ubuntu Release
`-Wstringop-overflow` in TLS test fixture
at `tests/test_owned_preauth_session.cpp:590`
remains unrelated.
**NOT RUN:** user's local persistent
`~/rdp-server/build/`, controlled
real positive keytab/client tickets
and GSS/TLS certificate-bound proof,
independent OS account/session policy,
Windows App or other external RDP
client or desktop. Authentication
refusal tests never authorize access.
**Next:** verified genuine positive
Kerberos/SPNEGO, GSS unwrap/wrap and
active TLS binding with explicit
test-only credentials, then separate
OS authorization before MCS replies
or remote desktop admission.

## Verified outgoing CredSSP selected TLS certificate continuity (2026-10-14)

**Prior exact known-green main:** `5777fa738fb94499356ba910643edd7f8a127026`,
[CI 38624268810](https://github.com/k1moradi/RDP-server/actions/runs/38624268810):
Linux/GCC 69/69, macOS/Clang,
Windows/MSVC 60/60 full CTests,
Debug and Release, SDK, ZIP/SHA-256
artifacts and documentation policy PASS.

**New implementation:**
`53184c7e4fdfb1c01f287933ff4ca0a6fdf63c0a`
changes the ORIGINAL
`src/server/security/credssp_tsrequest.{h,cpp}`
`TsRequestTlsReplyWriter`, the existing
`tests/test_owned_preauth_session.cpp`
fixture and `tests/CMakeLists.txt`
test registration, and updates
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/coding_standards.md`,
`docs/testing_standards.md` and this
validation ledger in the same commit.
Outgoing CredSSP responses now pin
the original finished TLS server SSL*
and the selected DER X.509 SHA-256
fingerprint from the FIRST queued
canonical v5/v6 reply. The writer
checks that certificate before
EVERY TLS write/retry, idempotent
Complete, successful release and
next response queue, using existing
`fingerprintActiveCredSspServerTlsCertificate`.
A mismatch on the same SSL object
closes and wipes pending DER and
the certificate fingerprint, without
a further SSL_write_ex. Already
submitted TLS data cannot be retracted.
No new authentication context,
socket listener or OS session.

**PASS:** [Actions 38674532102](https://github.com/k1moradi/RDP-server/actions/runs/38674532102)
completed SUCCESS for documentation
policy and all three protocol jobs:
Linux/GCC **72/72** and macOS/Clang,
Windows/MSVC **63/63** full CTests
in BOTH Debug and Release. ALL THREE
new tests
`transport.credssp-tls-reply-cert-pending`,
`transport.credssp-tls-reply-cert-completion`,
`transport.credssp-tls-reply-cert-backpressure`
PASS on all platforms. SDK installation
and downstream CMake consumer compile,
link and execution, three CPack ZIP
archives, three SHA256 checksum
manifests and artifact uploads all PASS.
CI commands: `cmake -S . -B build
-DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`
(with Linux `-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`),
`cmake --build build --config Debug
--parallel 2`, `ctest --test-dir
build --build-config Debug
--output-on-failure`; same-root
Release reconfigure/compile/CTest,
SDK install, downstream consumer,
CPack package/SHA256/upload.
Previous nonfatal Ubuntu Release
`-Wstringop-overflow` warning in
TLS fixture around line 590
remains. Prerelease SKIPPED (no tag).
**NOT RUN:** owner's local
`~/rdp-server/build`, genuine
positive Kerberos/GSS service
keytab and client tickets with
real confidential selected-TLS
public-key binding, independently
authorized OS account/session,
Microsoft RDP client or actual
desktop. Negative TLS continuity
tests never grant admission.
**Next:** authorized opt-in isolated
positive Kerberos/GSS TLS proof
and independent OS authorization
before MCS, graphics or desktop.

## Verified GSS acceptor certificate pin and opt-in real Kerberos probe build (2026-10-14)

**Prior verified main:**
`973561cefc37f9c4d9195276da2ce84862eae4ae`,
[CI 38674782887](https://github.com/k1moradi/RDP-server/actions/runs/38674782887)
Linux/GCC 72/72, macOS/Clang and Windows/MSVC
63/63 standard CTests in both Debug and
Release, SDK/packages/policy PASS.

**Implementation:**
`1f6740452f27332303ded71d4f5f23bb599b9726`
changes the existing optional Linux
`src/server/security/gssapi_spnego_acceptor.{h,cpp}`
and `gssapi_credssp_binding.cpp`
to retain the first TLS-selected X.509
SHA-256 fingerprint IN the GSS acceptor
rather than trusting `SSL*` pointer
plus whatever new per-frame reader the
caller constructs. Constant-time recheck
gates later GSS tokens, binding-only
and combined-final public-key proofs
and outgoing provider-bound reply
handoffs. Terminal reject cleanses
digest/principal and releases the
GSS context/explicit creds.
`CMakeLists.txt` and `tests/CMakeLists.txt`
introduce opt-in
`RDP_SERVER_TEST_REAL_KERBEROS=ON`
on Linux with mandatory explicit
`RDP_TEST_KRB5_SERVICE`,
`RDP_TEST_KRB5_KEYTAB` and
`RDP_TEST_KRB5_CCACHE` environment
values; NO host defaults, automatic
KDC, service activation or live
RDP listener. A non-default case
in the existing
`tests/test_owned_preauth_session.cpp`
compiles REAL MIT GSS client and
server exchanges through the
original OpenSSL TLS fixture,
confidential binding-only proof
and a fresh-reader/same-SSL
certificate substitution denial.
The binding-only diagnostic cannot
claim normative combined-final
MS-CSSP interoperability.
Same-commit roadmap/architecture,
coding/testing standards and
this validation ledger updated.

**PASS:** exact [Actions 38678010820](https://github.com/k1moradi/RDP-server/actions/runs/38678010820)
at implementation SHA above; all
four required jobs SUCCESS. Linux/GCC
**72/72**, macOS/Clang and
Windows/MSVC **63/63** CTests, EACH
Debug and Release, documentation
policy, three staged installed
SDK consumers and all three
CPack ZIP/SHA256 package uploads.
CI uses checkout-local `build/`:
`cmake -S . -B build
-DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`
plus Linux-only
`-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`,
build/CTest Debug; reconfigure SAME
root Release, build/CTest Release;
install/stage SDK, downstream
CMake consumer, CPack and checksums.
The optional real Kerberos probe
is COMPILED by Linux/GCC but NOT
registered/run in normal CI.
Prior nonfatal Ubuntu Release
test `-Wstringop-overflow` around
`tests/test_owned_preauth_session.cpp:594`
persists. No protocol prerelease tag.

**NOT RUN:** positive Kerberos/GSS
test with explicit separately
authorized service keytab and real
client ticket cache; confidential
GSS proof in that opt-in test,
normative last-token combined
MS-CSSP exchange with Microsoft
client, owner's local build,
independently approved OS
account/session or real desktop.
Do not call compilation positive
Kerberos acceptance.
**Next:** provision an isolated
external KDC/keytab/ticket ONLY
with explicit authorization,
execute opt-in test, verify combined
final SPNEGO/pubKeyAuth behavior,
then implement independent OS
session policy before MCS/desktop.

## Verified v6 CredSSP server failure TSRequest serializer and TLS writer (2026-10-14)

**Previously verified main:**
`c0aa5a2032da910c08ef982f5421dcc89166526e`,
[CI 38678271447](https://github.com/k1moradi/RDP-server/actions/runs/38678271447):
Linux 72/72 and macOS/Windows 63/63
CTest, Debug+Release, SDK/policy/packages PASS.

**Implementation** `6925ac11a49b3d71a6ffa120b688ca95a0a088af`:
`src/server/security/credssp_tsrequest.{h,cpp}`
adds a v6-only canonical
`encodeCredSspServerFailureTsRequest`
for [0] version plus [4] signed
32-bit unsuccessful NTSTATUS,
restricted to 0xC000006D and
0xC00000BB. Other versions,
arbitrary NTSTATUS, mixed
credentials/tokens/binding/nonce
and success-shaped error replies
cannot be emitted. The ORIGINAL
`TsRequestTlsReplyWriter` gains
`queueFailureReply`, using ONE
private `queueEncoded` for both
old provider token/binding replies
and error DER. It retains exact
SSL*/certificate continuity,
OpenSSL WANT retry buffer lifetime,
single pending reply, and securely
wipes discarded DER on failure.
Upon completed failure delivery
the reply is released and the
writer closes TERMINALLY so no
other response follows.
The code deliberately DOES NOT
automatically dispatch NTSTATUS
from unverified provider states
or authorize any client/OS session.

FOUR portable CTests were added
to the EXISTING
`tests/test_owned_credssp_tsrequest.cpp`,
`tests/test_owned_preauth_session.cpp`
and original `tests/CMakeLists.txt`,
with same-commit changes to
`docs/ROADMAP.md`, architecture,
coding and testing standards
and this ledger.
**PASS:** [Actions 38683205424](https://github.com/k1moradi/RDP-server/actions/runs/38683205424)
exact implementation commit:
documentation-policy,
Linux/GCC **76/76** Debug and
Release, macOS/Clang **67/67**
Debug and Release, Windows/MSVC
**67/67** Debug and Release,
including all four new
`security.credssp-server-failure-wire`,
`security.credssp-server-failure-rejections`,
`transport.credssp-tls-failure-reply-wire`,
`transport.credssp-tls-failure-reply-rejections`
PASS across all operating systems.
All 3 installed CMake SDK consumers
compiled/linked/ran, 3 SDK ZIP and
SHA256 archives uploaded, project
policy CTests PASS. The existing
CI commands use ONE checkout-local
`build/`: CMake configure
`-DCMAKE_BUILD_TYPE=Debug` with
`-DBUILD_TESTING=ON` and Linux-only
`-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`,
build/CTest Debug, same-root
Release reconfigure/build/CTest,
installed consumer, CPack ZIP,
SHA256 and artifact upload.
Known unrelated Ubuntu Release
`-Wstringop-overflow` at TLS
fixture line 594 remains nonfatal.
Protocol prerelease SKIPPED
(no release tag).
**NOT RUN:** owner's persistent
`~/rdp-server/build/`, opt-in
genuine MIT Kerberos using an
explicit keytab and client cache,
GSS and selected TLS pubKeyAuth
positive proof, actual GSS provider
error-code dispatch, independent
OS user authorization, Microsoft
RDP client or desktop.
**Next:** real isolated/authorized
positive GSS proof test, then
explicit terminal failure-message
dispatch and separate OS session
policy BEFORE issuing live MCS.

## Pending GSS real-provider failure to CredSSP v6 error queue (2026-10-15)

**Baseline exact main:** `ebc794738552f5411ebe4d2222000f8ae94183f2`,
[CI 38708915869](https://github.com/k1moradi/RDP-server/actions/runs/38708915869)
PASS, Linux/GCC **86/86**, macOS/Clang and Windows/MSVC
**77/77** CTests BOTH Debug/Release, installed SDK
consumer, ZIP/SHA256 packages and docs policy.
Owner reports prior **77/77** local PASS. This is
NOT evidence for the new security functionality.

**Scope:** `src/server/security/gssapi_spnego_acceptor.{h,cpp}`
now distinguishes actual configured MIT GSS provider/
policy rejection from local syntax, configuration,
transport provenance, TLS fingerprint and allocation
errors. A rejected provider state still securely tears
down GSS credentials, context, verified principal and
pinned certificate. Only an initial/continuing
version-6 TLS-derived, syntactically valid nego-only
TSRequest on the same selected certificate can queue
the original canonical `STATUS_LOGON_FAILURE`
`TSRequest.errorCode` using the same one-pending
`TsRequestTlsReplyWriter`. New
`SpnegoStatus::FailureQueued` signifies one
15-byte DER record QUEUED for caller-managed TLS
send/release, not successful GSS, permitted OS
admission or a completed TLS record. All other
failures remain silent terminal rejection.

**Tests:** one new default Linux-only CTest
`security.gssapi-failure-reply-denials` within
existing `tests/test_owned_preauth_session.cpp`;
one more `security.gssapi-real-kerberos-tls-failure`
is registered ONLY with the already optional
`RDP_SERVER_TEST_REAL_KERBEROS=ON` and explicit
owner-controlled TERMSRV service, FILE:/ keytab
and FILE:/ client cache. Its provider rejection
and exact 15-byte TLS reply are NOT RUN in default
CI or without real credentials. Same-commit
ROADMAP, architecture, coding and test standards.
Expected default **77 portable / 87 Linux GSS** CTests.

**NOT RUN at authoring:** new-head Linux/macOS/
Windows CI, owner-local new compile/CTest, real
Kerberos service provider/keytab, live Microsoft
client, OS authorization, complete CredSSP
combined-last-token acceptance, MCS or desktop.
Use owner's ONE persistent `~/rdp-server/build`:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next:** exact-head CI and owner-local verification,
then separately authorized opt-in real provider
failure/positive TLS proof and OS identity gate.

## Verified T.128 Share Data Header syntax gate (2026-10-15)

**Prior verified baseline:** `8aea09a101fe1394c6c60145fef42fa002514315`,
[Actions 38705731398](https://github.com/k1moradi/RDP-server/actions/runs/38705731398)
PASS, with Linux/GCC **84/84** and macOS/Clang,
Windows/MSVC **75/75** full Debug/Release CTests,
installed SDK consumer/package and documentation policy.
Owner reports **75/75 local** on that prior head. This
is not evidence for the new Share Data code.

**Implementation:** extend the original first-party
`src/server/transport/mcs_channel_connection.{h,cpp}`
with a bounded, zero-copy Share Data Header parser that
REUSES the exact existing Share Control Header decoder.
MS-RDPBCGR 2.2.8.1.1.1.2's shareID, ignored pad1,
streamID, uncompressedLength, pduType2, compressedType
and compressedLength fields are decoded as syntax only;
24 normative type2 values; the stream 0/Synchronize
compatibility exception; uninitialized Client Font List
uncompressedLength never treated as a frame bound.
Compressed frames remain explicitly unsupported, with
no borrowed application payload; no TLS, MCS ownership,
decompression, graphics, authentication or OS admission.
Two CTests `transport.share-data-header-wire` and
`transport.share-data-header-rejections` are added to
the existing `test_owned_mcs_connect_initial.cpp` binary
and `tests/CMakeLists.txt` registry. Expected totals:
**77** portable / **86** Linux GSS-enabled. In the SAME
implementation commit, update the sole living ROADMAP,
architecture, coding/testing standards and validation ledger.

**PASS:** implementation `9bc9e041419b4a932dc988a51f1f3e920ac82ba3`,
[Actions 38708579033](https://github.com/k1moradi/RDP-server/actions/runs/38708579033)
Linux/GCC **86/86**, macOS/Clang and Windows/MSVC
**77/77** CTests in BOTH Debug and Release. Both new
Share Data wire/negative behavior tests passed everywhere;
staged installed SDK consumer, packages and docs-policy
PASS. Prerelease publish SKIPPED (no release tag).
**NOT RUN:** owner's new local rebuild/CTest, sanitizer,
actual GSS/keytab/tickets, TLS live Share Data dispatch,
optional security headers, OS-authorized licensed/activated
session, nested input, graphics, clipboard or actual
Microsoft RDP client acceptance.
Local owner's one reused build root:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`;
`cmake --build build --config Debug --parallel 2`;
`ctest --test-dir build -C Debug --output-on-failure`.
**Next:** owner-local validation on the single build root,
then controlled genuine Kerberos/TLS and independent OS
session authorization before live Share Data dispatch.

## Verified offline T.128 Share Control Header decoding (2026-10-15)

**Prior verified base:** main
`424a35a8ceeb2a32fc553f334cfdcdfeebf5e2a6`,
[CI 38701851845](https://github.com/k1moradi/RDP-server/actions/runs/38701851845)
completed successfully with Linux/GCC **82/82**,
macOS/Clang and Windows/MSVC **73/73** CTests per
Debug/Release, SDK consumers, ZIP artifacts and policy.
Owner reports local **73/73** on that same earlier head.
Those tests do not prove the new parser.

**New scope:** existing portable
`src/server/transport/mcs_channel_connection.{h,cpp}`
adds `parseRdpShareControlHeader` to accept a previously
isolated complete six-byte little-endian T.128
TS_SHARECONTROLHEADER with declared-size equality, version
1 and known PDU type. `totalLength=0x8000` returns
`FlowPduIgnored` without a payload view, as MS-RDPBCGR
2.2.8.1.1.1.1 requires. The result's borrowed body
and source ID are *syntax*, not a session capability,
security-header classifier or OS admission.
Two tests in the existing
`tests/test_owned_mcs_connect_initial.cpp` executable:
`transport.share-control-header-wire` and
`transport.share-control-header-rejections`. Single
`tests/CMakeLists.txt` registry; expected **75**
portable / **84** Linux GSS-enabled CTests.
Same atomic implementation commit updates the
single living ROADMAP TODO and architecture, coding,
testing and validation docs.

**PASS:** implementation `77fd1be92c0f4dcff60962d645a39af9b23c96de`,
[Actions 38705203733](https://github.com/k1moradi/RDP-server/actions/runs/38705203733):
Linux/GCC **84/84**, macOS/Clang and Windows/MSVC
**75/75** CTests in each Debug and Release, including both
new Share Control test groups. Documentation policy,
staged SDK downstream consumer and ZIP/SHA256 packages PASS.
Prerelease publication SKIPPED because no tag was created.
**NOT RUN:** owner's new local build/CTest, sanitizers,
actual TLS security-header stripping, genuine GSS,
OS admission, nested Share Data, licensing, external
clients, desktop and clipboard.
Use the single `~/rdp-server/build/`:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next gate:** exact-commit cross-platform CI; later
real authenticated channel/security context and
independent OS session authority before dispatch.

## Pending T.125 server Send Data Indication offline encoder (2026-10-15)

**Previous exact-head baseline:** `cd50346be4df281b7fc207c5126072555a3eba63`,
[Actions 38696744690](https://github.com/k1moradi/RDP-server/actions/runs/38696744690)
PASS: Linux/GCC **80/80**, macOS/Clang and Windows/MSVC
**71/71** Debug and Release CTests, SDK packages/consumer
and documentation policy. The owner additionally reports
local **71/71** PASS at the previous main. These do NOT
constitute evidence for this increment.

**Implementation:** the existing
`src/server/transport/mcs_channel_connection.{h,cpp}`
now emits bounded T.125 server SendDataIndication
(choice 26, 0x68) into a caller-owned `std::span`,
with no heap allocation or TLS I/O. Validates assigned
UserId, channel nonzero, 2-bit priority/segmentation,
7/14-bit PER length up to 16383 and full output capacity
before changing any output. `std::memmove` handles
input/output overlap before header stores. The existing
`tests/test_owned_mcs_connect_initial.cpp` and
`tests/CMakeLists.txt` add
`transport.mcs-send-indication-wire` and
`transport.mcs-send-indication-rejections` to the
single registry. Expected portable **73** CTests,
Linux GSSAPI **82**. Architecture, roadmap, coding
and testing standards updated in SAME code commit.

**PASS:** exact implementation
`8c9fabeb02fce7ede13abfb42631d3b7f35a4fc1`,
[GitHub Actions 38701524465](https://github.com/k1moradi/RDP-server/actions/runs/38701524465):
Linux/GCC **82/82**, macOS/Clang and Windows/MSVC
**73/73** CTests in EACH Debug and Release; new
`transport.mcs-send-indication-wire` and
`transport.mcs-send-indication-rejections` PASS
everywhere. Documentation-policy, staged installed SDK
consumer execution and all three ZIP/SHA256 artifacts
PASS. Prerelease publication SKIPPED (no release tag).
**NOT RUN:** owner's new local CTest, sanitizers,
live TLS output, authorized GSS/Kerberos and OS
admission, joined MCS state, real desktop or
Microsoft client.
Owner's one build root commands:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next:** exact-head CTests and SDK consumer/policy CI;
then verified true GSS/TLS + separate OS identity gate
before any live application data emission.

## Pending T.125 client Send Data Request syntax intake (2026-10-14)

**Prior exact baseline:** main
`05f2708cc8b326983c406b643bee1d47e5e166d0` passed
[CI run 38685374294](https://github.com/k1moradi/RDP-server/actions/runs/38685374294);
the owner reports **69/69** local CTests PASS for the earlier
code. These results do NOT verify this increment.

**New implementation:** existing
`src/server/transport/mcs_channel_connection.{h,cpp}`
parses T.125 SendDataRequest choice 25, validates complete
TPKT/X.224 and PER fields, and provides a read-only borrowed
userData view with no allocation. A valid syntactic packet does
not establish a joined channel, decrypted provenance, user
identity, OS desktop access, or any session admission.
Two behavior cases are added to the existing
`tests/test_owned_mcs_connect_initial.cpp` and
`tests/CMakeLists.txt`: `transport.mcs-send-data-wire` and
`transport.mcs-send-data-rejections`, with expected 71
portable CTests (80 when the Linux GSS cases are enabled).
The roadmap, architecture, coding and testing standards
are updated in the same commit.

**First CI result FAIL:** implementation
`c1f9e5458132c40b149e8ec5f0e6083addff8715`,
[Actions 38696231297](https://github.com/k1moradi/RDP-server/actions/runs/38696231297):
Linux/GCC Debug **79/80**, macOS/Clang Debug **70/71**,
both failed ONLY `transport.mcs-send-data-wire`, while
the new negative test passed. First failure:
`tests/test_owned_mcs_connect_initial.cpp:760` assertion
on `result.request.userData[0]`. Root cause is a test-only
lifetime violation: `parseMcsChannelRequest(frameDomainPdu(mcs))`
returns a borrowed span into a temporary vector that dies
at the end of the same statement. Fix test to hold the
complete TPKT in a stack-scoped `const auto frame` until
all view assertions are complete; assert the span's exact
offset as a regression against future accidental copies.
No production parser change. Windows results for that first failed attempt were not
finalized when the correction was authored.

**Verified correction:** `72af29fddc2424fcc7f4edbd579e2b313ef25f48`,
[Actions 38696503496](https://github.com/k1moradi/RDP-server/actions/runs/38696503496):
Linux/GCC **80/80** CTests; macOS/Clang and Windows/MSVC
**71/71** CTests, in BOTH Debug and Release. Both
`transport.mcs-send-data-wire` and
`transport.mcs-send-data-rejections` PASS across all
three operating systems. Installed SDK consumer, ZIP/SHA256
package upload and project documentation-policy PASS;
prerelease publishing SKIPPED (no version tag).
The only correction since initial implementation is to
keep the test input packet alive through borrowed-view
inspection; the production decoder is unchanged.

**NOT RUN:** owner-local corrected compile and CTest
(the owner machine is not mounted), new exact-head platform
CI, SDK package/consumer tests, ASan/UBSan, real Kerberos,
Microsoft RDP clients, channel authorization, licensing,
graphics and desktop. To validate on the one reused owner
build root: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next gate:** exact-head full CI and owner-local regressions,
then independently authorized post-auth MCS lifecycle.

## Verified offline MCS Disconnect Provider Ultimatum (2026-10-14)

**Prior main and owner-local PASS:** `36926462d34726f355279367a2ba2f27e93d2095`.
The supplied Linux Debug command in the one reused
`~/rdp-server/build/` compiled successfully and CTest
reported **67/67 PASS**, including the CredSSP single-byte
tag rejection case. [GitHub Actions 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429)
also succeeded for that baseline. These results do
not establish acceptance of the NEW increment.

**Implementation:** `src/server/transport/mcs_channel_connection.{h,cpp}`
gains a typed, fixed-array, zero-allocation nine-byte
MCS Disconnect Provider Ultimatum encoder; incoming
requests recognize properly framed disconnects without
interpreting peer reasons. No authentication/authorization,
socket/SSL output, new binary, independent controller or
live session state is added. Two portable regression
groups in the existing `tests/test_owned_mcs_connect_initial.cpp`
are registered in `tests/CMakeLists.txt`: expected standard
test total **69**, up from 67. Same implementation commit
updates the one ROADMAP TODO and canonical architecture,
coding/testing and validation standards.

**PASS:** exact implementation
`ed4b0c0a05981f573bc6b8369893f33d1e71549d`,
[Actions 38685111404](https://github.com/k1moradi/RDP-server/actions/runs/38685111404):
Linux/GCC **78/78** CTests, macOS/Clang and Windows/MSVC
**69/69** CTests, EACH Debug and Release; both new disconnect
cases pass everywhere. Documentation-policy, installed SDK
consumer and ZIP/SHA-256 package uploads also PASS. The
prerelease publication job was SKIPPED without a release tag.
**NOT RUN:** owner's new local compile/CTest, sanitizers,
live Microsoft RDP client, actual encrypted TLS disconnect
and socket close, genuine Kerberos, independent OS
account/session authorization or desktop.
Use `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`
within the owner's existing checkout/build directory.
**Next gate:** full exact-head CI/owner-local tests, then
authorized TLS/session lifecycle and GSS/OS admission.

## Verified single-byte CredSSP DER fail-fast intake (2026-10-14)

**Prior verified main:** `1cce799dc1aa7a55e3cb343dd09823052a1c23a6`,
[Actions 38683456755](https://github.com/k1moradi/RDP-server/actions/runs/38683456755)
completed successfully. This incremental change uses that head as
its parent; the new commit SHA is available in GitHub history
after the atomic push.

**Change:** `src/server/security/credssp_tsrequest.cpp` now
checks the first DER tag *before* returning NeedMore at the end
of an input event. `tests/test_owned_credssp_tsrequest.cpp`
reuses `security.credssp-stream-rejections` to test all 255
invalid single-byte initial tags, exact consumed count,
fail-closed replay, and the valid first-tag control.
Affected canonical roadmap, coding and testing docs are updated
in this same implementation commit.

**PASS:** implementation
`36926462d34726f355279367a2ba2f27e93d2095`,
[Actions 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429)
Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release,
SDK, package, documentation-policy and all protocol tests.
Owner-local `~/rdp-server/build/` Linux Debug build and
**67/67** CTest PASS from the supplied full command/output.
**NOT RUN:** sanitizers, positive Kerberos, Microsoft
external client or desktop admission. The specified validation commands are
`cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2`,
and `ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure`.
**Next gate:** pursue controlled GSS failure/identity handling
without granting OS session access. Verified offline CI does
not authorize an MCS session or desktop.
