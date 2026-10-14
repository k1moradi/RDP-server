# RDP-server protocol roadmap and acceptance gates

## Target

Develop an independently maintained, secure, standards-compliant C++23 RDP
server protocol stack, portable across OSes via system adapters. Use native
RDP capabilities, not VNC, xrdp, clipboard injection helpers, or nonstandard
screen-sharing workarounds.

## Status: foundation, not release

Current code includes X.224/TPKT, selected MCS/GCC parsers, negotiation,
CredSSP/DER and CLIPRDR helpers, verified graphics algorithms and portable
testable core. It does **not** yet operate a complete authenticated RDP
server session. The library has no shipping daemon/installer.

## Delivery order

1. **Wire interoperability:** bounded TPKT/X.224, security negotiation,
   MCS/GCC, TLS, CredSSP/NLA credential and channel binding; state-machine
   fuzzing against hostile and truncated PDUs
2. **Authenticated session:** implement complete server-side MCS attach,
   channel join, licensing semantics, capability exchange, Demand Active,
   Confirm Active, share data, transport lifecycle and disconnect
3. **Virtual channels:** CLIPRDR/RDPSND/DRDYNVC channel routing,
   fragmentation/reassembly, concurrent lifecycle and error semantics
4. **Graphics:** standards-compliant desktop update path, RDPGFX and negotiated
   H.264/RemoteFX/bitmap codecs; independent frame coherence and RDP client
   acknowledgement/backpressure
5. **Platform adapters:** Linux (X11/Wayland as separately negotiated backends),
   macOS, Windows and other platforms for capture, input, cursor, session and
   identity with the same protocol-independent C++ core
6. **End-to-end clipboard:** negotiate Unicode, PNG and DIB; validate
   generation correctness and X11/OS clipboard ownership; require a trusted
   macOS screenshot paste into Firefox with a genuine non-null
   `ClipboardEvent.clipboardData.items[].getAsFile()` of type `image/png`
7. **Performance, packaging and release:** benchmark against real Windows
   App and FreeRDP clients on multiple OSes, exercise slow/fast links,
   instrument latency, and ship a standalone installable RDP server only
   once all gates pass

## Acceptance policy

- Offline CTest and static library compilation are foundation gates.
- Native protocol integration, TLS/NLA security, external clients, graphics,
  input, clipboard, session admission, OS backends and real desktop access
  are **not yet accepted**; never infer them from a green unit test.
- No new Git branches may be created by assistants/agents without an explicit
  request from the owner.
- Preserve attributions and third-party licenses for upstream-inspired code,
  but do not depend on an xrdp daemon, patched chansrv or VNC runtime.

## Living TODO — authoritative project checklist

This is the **single current TODO list**, required context on **every
prompt**. Update the *same* item when implementation, blocker or evidence
changes; don't create another milestone list. Apply [VISION](VISION.md)
and the four mandatory [coding](coding_standards.md),
[testing](testing_standards.md), [build](compile.md) and
[benchmark](benchmark.md) standards. Checkboxes require measured
acceptance evidence; no synthetic completion claims.

### P0 — Preserve work and implement a native RDP server

- [x] Independently compile/test C++23 static protocol foundation;
  historical Actions run 38516048776 succeeded at 77c94c75b467.
  This **is not** a working RDP desktop server.
- [x] Retire the obsolete legacy-source migration guide and both import
  scripts by owner request. The original project was **not fully
  imported**; only the maintained, checked-in first-party code is in
  scope for ongoing development. Additional historical source requires
  a separately authorized and reviewed integration, not an automatic
  import. This is a cleanup gate, not a functional RDP milestone.
- [ ] Implement bounded X.224/TPKT/MCS/GCC network listener and complete
  standards-compliant server connection state machine with external-client
  handshake and malformed-packet evidence.
  **Completed partial increment at `988938a90f8adbae4e07714ac636af3eb0640011`:**
  bounded incremental plaintext Connection Request intake, exact TCP
  consumed-byte accounting, correct negotiation response/terminal failure,
  all request split points and malformed-length negative tests.
  **PASS:** [Actions run 38536987879](https://github.com/k1moradi/RDP-server/actions/runs/38536987879)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  registered protocol and policy CTests passed.
  The *overall* milestone stays **open**: a real TCP listener, TLS provider,
  authenticated session, MCS response and external-client handshake
  remain **NOT RUN / unimplemented**.
  **Additional partial increment `18262c0e4bf9bc4ecec4c2d56b069d4fc723b1f1`:**
  the existing preauth owner requires exactly one completed X.224
  reply write before accepting a TLS transition. Premature TLS,
  failed/partial and repeated acknowledgments fail closed.
  **PASS:** [Actions run 38537586258](https://github.com/k1moradi/RDP-server/actions/runs/38537586258)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
  The overall listener/TLS/authentication milestone is still open;
  **no real socket, TLS provider or external client was tested**.
  **Verified increment at `49c6006d47476184f7448028cd332e377ec9bd0b`:** reuses the same preauth
  buffer to reassemble exactly one decrypted RFC 1006/X.224 Data TPDU
  carrying a BER MCS Connect Initial and GCC Conference Create Request.
  The native test exercises every split/truncation point, coalesced
  next-PDU bytes, invalid TPKT length/X.224 type, BER errors and
  replay/close. This is NOT a real TLS or admitted RDP session.
  **PASS:** [Actions run 38541509607](https://github.com/k1moradi/RDP-server/actions/runs/38541509607) on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy. **NOT RUN:** live TLS/NLA, host listener and external client.
  **Next boundary:** real TLS provider plus authenticated session
  policy and complete MCS response handling.
  **Current partial security increment (CI pending):**
  `PreauthConnectionStream` requires a completed, server-role
  OpenSSL TLS 1.2+ session with selected certificate/cipher, instead of
  accepting a caller-supplied Boolean. The existing transport CTest
  now exercises an actual in-memory OpenSSL TLS handshake and negative
  wrong-role, pre-handshake, null, early and replay transitions.
  This does **not** implement socket TLS I/O, trusted OS session
  authorization, CredSSP/NLA or MCS Connect-Response.
  **First CI result:** macOS and documentation-policy PASS,
  Windows Compile Debug FAIL at `a25b5186398e4a5619baea2998a61596fa7b2887`
  ([Actions run 38551275680](https://github.com/k1moradi/RDP-server/actions/runs/38551275680))
  because OpenSSL's platform includes exposed a `min` macro
  affecting the existing `std::min(...)` intake calls.
  The follow-up fixes OpenSSL header isolation and call syntax.
  **PASS:** fixed OpenSSL include/Windows macro handling at
  `edfaf2e7ea684ab5adc77bf58441ff467288f818`, verified by
  [Actions run 38551496274](https://github.com/k1moradi/RDP-server/actions/runs/38551496274):
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  all passed Debug/Release full CTests, downstream SDK consumer
  and per-OS ZIP/checksum artifact uploads.
  **NOT RUN:** real socket TLS peer, trusted credentials/NLA,
  OS desktop admission, external RDP clients or owner's local
  build of this new commit. **Next:** integrate an authenticated
  TLS transport/session lifecycle without permitting OS admission
  before CredSSP/identity authorization.
  **Verified TLS application-record increment `a226f15827e9da48ad7a91b7cfa53528c3498802`:** the existing
  preauth stream now associates the completed OpenSSL server `SSL*`
  with the connection and uses `SSL_read_ex` to decrypt and parse
  precisely one bounded MCS/GCC TPKT. WANT_READ/WANT_WRITE do not
  close the connection; EOF, malformed data, swapped SSL handles
  and replay fail closed. The memory-BIO test drives actual encrypted
  TLS application records at every split boundary, coalesced trailing
  PDU, invalid header and early close. Neither a socket listener
  nor CredSSP/OS admission is implemented.
  **PASS:** [Actions run 38557465241](https://github.com/k1moradi/RDP-server/actions/runs/38557465241),
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy; all
  Debug/Release protocol and project-policy CTests, staged SDK install,
  downstream consumer and platform ZIP/checksum uploads passed.
  **NOT RUN:** user's local build of this exact head, external client,
  TCP TLS listener, OS identity admission and desktop interaction.
  **Next:** nonblocking socket adapter and authenticated session policy,
  without equating a TLS handshake with user authentication.
  **Verified partial-send protocol increment at `98f6fdc60d513d47a87a78fadf1aa6be387da28b`:**
  `PreauthConnectionStream` now owns the 19-byte X.224
  Confirm/Failure response and tracks byte-accurate nonblocking
  write progress. Zero-byte output is retryable; overrun, premature
  TLS and replay fail closed; a rejected negotiation's response
  drains before transport closure. The existing preauth executable
  has an independent `transport.x224-confirm-partial-writes` CTest
  covering all 20 split boundaries, bytewise writes, cancellation,
  malformed accounting and both negotiation outcomes. Expected
  CTest total: **21**, up from 20 for a substantive new behavior.
  **PASS:** [CI run 38561127854](https://github.com/k1moradi/RDP-server/actions/runs/38561127854)
  for Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  all Debug/Release CTests, installed SDK consumer, ZIP and SHA-256
  artifacts. Ubuntu logs explicitly show **21/21 PASS** in both
  configurations. **NOT RUN:** owner-local new build, real TCP listener,
  external clients, NLA, OS admission, desktop interaction.
  **Next:** nonblocking network adapter and authenticated RDP session.
  **Verified native TCP adapter increment `dd3a806f97b13e6db18affd689c6321bfa009813`:**
  `PreauthTcpAdapter` wraps the existing sole preauth owner and drives
  exact-prefix 4-byte TPKT/declared request `recv`, followed by the
  byte-accurate pending X.224 Confirm/Failure `send`. A thin native
  socket adapter maps Linux/macOS/BSD and Windows recv/send errors to
  nonblocking outcomes. No extra encrypted TLS records can be read
  prematurely, even if coalesced on TCP. Scripted event-loop regressions
  exercise all 20 CR split positions, one-byte reads/writes, would-block,
  corrupted headers, EOF, short output, overreported counts, complete
  NEG_FAILURE and cancellation.
  **PASS:** [Actions run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
  passed Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
  all Debug/Release CTests, SDK installation, downstream consumer
  and three ZIP/SHA-256 artifacts. Ubuntu explicitly reports
  **23/23 PASS** in Debug and Release.
  **NOT RUN:** owner-local new build, actual connected native
  socket runtime, listening server, live TLS network handshake,
  CredSSP/NLA, MCS Connect-Response and authenticated desktop.
  **CI compatibility note:** the documentation-evidence rerun
  [38564061700](https://github.com/k1moradi/RDP-server/actions/runs/38564061700)
  encountered a macOS Debug compile **FAIL** with OpenSSL 4.0.3:
  `X509_get_subject_name` now returns `const X509_NAME*`,
  invalidating the synthetic certificate fixture's mutable cast.
  A follow-up constructs its own `X509_NAME` and assigns it
  through `X509_set_subject_name`, avoiding reliance on
  the changed mutable return type.
  **PASS:** corrected `5c4f3ad7273d17948327b7d351ff9840de2b0395`
  in [CI run 38564403002](https://github.com/k1moradi/RDP-server/actions/runs/38564403002):
  Ubuntu/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
  Debug/Release **23 CTests**, installed consumer and three SDK ZIPs.
  macOS selected OpenSSL **3.6.4** on the passing run;
  the corrected fixture's OpenSSL 4 runtime/compiler gate remains
  **NOT RUN**. **Next:** verify OpenSSL 4 explicitly, complete
  actual live TLS/socket I/O, authentication and MCS response.
- [ ] Implement TLS, CredSSP/NLA and independently verified OS session
  authorization, including security downgrade and failure tests.
- [ ] Implement licensing, capabilities/share activation, virtual-channel
  routing, graphics delivery, keyboard/pointer and correct lifecycle.

### P1 — Real client features and performance

- [ ] Unify CLIPRDR Unicode, PNG/DIB, file streaming, transfer generations
  and local OS clipboard ownership under one C++23 session authority.
  Never require FUSE or `~/thinclient_drives` by default.
- [ ] Verify macOS screenshot through RDP into Firefox produces a genuine
  synchronous PNG File, not merely successful generic X11 transfer.
- [ ] Integrate isolated Linux/X11/Wayland, Windows and macOS desktop,
  clipboard and input adapters; test real Microsoft/FreeRDP clients.
- [ ] Measure native server CPU/RAM, bandwidth, graphics and clipboard
  p50/p95/p99; only then claim performance improvements.

### P0 — Standards and repeatable automation

- [x] The canonical agent policy, four mandatory domain standards,
  behavior-named CTest suites, documentation co-change checker and
  local-home-checkout/single-build-root CMake guards passed
  [Actions run 38535723210](https://github.com/k1moradi/RDP-server/actions/runs/38535723210)
  at `e1843b07c8772588f29e45a9b8e328e51c59e2ff`.
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  jobs all succeeded. This proves the **CI's isolated checkout
  exception** and offline protocol/policy gates only; the owner's
  persistent `~/rdp-server/build/` and real clients were NOT RUN.
- [x] Automate Debug/Release C++23 builds and full offline CTest,
  staged SDK installation, downstream package consumer verification,
  per-OS ZIP archives and SHA-256 manifests. **PASS:** commit
  `1aa025960288d40f476e85c5a9c5f97b06bebf20`,
  [Actions run 38543429777](https://github.com/k1moradi/RDP-server/actions/runs/38543429777):
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  **three uploaded protocol SDK packages verified**.
- [ ] Exercise automatic tagged GitHub **prerelease publication**
  (`protocol-vX.Y.Z` corresponding to CMake project version, from `main`).
  Release job is configured and gated on successful matrix/maintenance
  checks, but was **SKIPPED / NOT RUN** because no release tag was
  created. Publishing an SDK is **not** installation, activation or
  authenticated end-to-end deployment of an RDP server.
- [x] Consolidate all seven non-entrypoint root Markdown documents
  under `docs/` while retaining `README.md`, `AGENTS.md`,
  `CLAUDE.md`, `CODEX.md`, `agent.md`, `LICENSE` and `NOTICE`
  at repository root. Rebase 47 links, fix attribution package
  install path and enforce the layout using the canonical policy CTest.
  **Initial FAIL:** [run 38544805819](https://github.com/k1moradi/RDP-server/actions/runs/38544805819)
  at `e3e6a7576f530280a1095f8e15f058d7da07f52d` uncovered
  missing CMP0057 in standalone `cmake -P` policy script (10 native
  protocol tests still passed on Ubuntu).
  **PASS:** corrected `list(FIND)` at
  `f68d1d417424823eed7856761ff95f0ebe1eabb2` in
  [Actions run 38544988535](https://github.com/k1moradi/RDP-server/actions/runs/38544988535):
  Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  passed full Debug/Release CTests, SDK installation, downstream
  consumer and package upload.
  **NOT RUN:** owner-local builds, real clients and service deployment.
- [ ] Expand reusable sanitizer, parser-fuzz, security-negative and real
  client acceptance suites as native runtime code becomes available.
  **Verified CTest reporting increment at `1e11327f2b74ff7e676fbb3bb7200491718a779f`:** Register the existing
  preauth test executable as ten independent behavior-named CTests
  (initial state, request fragmentation/outcomes, reply ordering,
  real TLS handshake, malformed X.224, decrypted MCS fragmentation
  and rejection, encrypted TLS record fragmentation and rejection).
  Keep one shared binary and all preexisting assertions. This changes
  the displayed CTest total from **11 to 20**; it does not mean nine
  newly invented protocol features or that the server can accept users.
  **PASS:** [Actions run 38559221423](https://github.com/k1moradi/RDP-server/actions/runs/38559221423):
  Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  succeeded, including Debug/Release full CTests, installed
  downstream consumer, ZIP and SHA-256 artifacts. Ubuntu logs
  explicitly confirmed **20/20 passed** in each configuration.
  **NOT RUN:** owner's local CTest after this change, external RDP
  client, authenticated session or desktop. Next development boundary:
  actual nonblocking TLS socket adapter and CredSSP/NLA admission.


Each implementation updates the relevant item with exact SHA, test
PASS/FAIL/BLOCKED/NOT RUN, first failing boundary and next smallest step.
Put detailed lessons into the appropriate domain standard, not new files.
