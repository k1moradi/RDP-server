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
**46**. **NOT RUN:** new exact-head GCC/Clang/MSVC
Debug/Release CI, SDK packaging, owner's local build,
real GSS/SPNEGO handshake, TLS public-key binding,
credential verification, OS session authorization,
NLA security selection, MCS response emission,
external client and desktop access.
**Next:** cross-platform CI; then a trusted authenticated
CredSSP/SPNEGO and OS authorization provider, integrated
with the sole preauthentication owner.
