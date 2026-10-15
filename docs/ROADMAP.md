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
4. **Graphics (H.264 first, x264 software encoder):** deliver a negotiated
   RDPGFX AVC420-only desktop update path with damage-aware capture, persistent
   reference frames, bounded latest-frame scheduling, client ACK/backpressure
   and correct surface/resize lifecycle. Use a statically linked x264 software
   encoder behind a minimal C++23 RAII adapter, without FFmpeg. ClearCodec,
   Planar and RemoteFX are not prerequisites for the first usable server.
5. **Platform adapters:** Linux (X11/Wayland as separately negotiated backends),
   macOS, Windows and other platforms for capture, input, cursor, session and
   identity with the same protocol-independent C++ core
6. **End-to-end clipboard:** implement MS-RDPECLIP/CLIPRDR for Unicode text,
   PNG/DIB/DIBV5 screenshots and on-demand copied-file streaming. Prefetch
   bounded text/compressed images after client advertisement, await readiness
   without blocking session/desktop event loops, and respect X11/Wayland/OS
   clipboard ownership. RDPDR drive redirection is separate and optional;
   file clipboard must not require FUSE or whole-file caching. Accept with
   real Microsoft clients, including a trusted macOS screenshot paste into
   Firefox yielding a non-null synchronous `image/png` File.
7. **Performance, packaging and release:** establish a real-client H.264-only
   baseline first with current Microsoft Windows App (Windows/macOS) and
   Windows 11 Remote Desktop Connection; FreeRDP remains a useful additional
   diagnostic client. Only after a usable server is verified, benchmark
   ClearCodec on representative graphical desktop workflows. Exercise
   slow/fast links and ship a standalone installable server only once
   all required authentication, usability and reliability gates pass

## Acceptance policy

- Offline CTest and static library compilation are foundation gates.
- Native protocol integration, TLS/NLA security, external clients, graphics,
  input, clipboard, session admission, OS backends and real desktop access
  are **not yet accepted**; never infer them from a green unit test.
- No new Git branches may be created by assistants/agents without an explicit
  request from the owner.
- Preserve attributions and third-party licenses for upstream-inspired code,
  but do not depend on an xrdp daemon, patched chansrv or VNC runtime.
- Target **practical interoperability with current Microsoft RDP clients**,
  not an official Microsoft certification claim. The first graphics milestone
  deliberately supports only negotiated H.264 for encoded bitmaps; it does
  not claim full MS-RDPEGFX implementation conformance, which specifies
  ClearCodec support. Reject sessions lacking compatible AVC capabilities
  cleanly instead of sending an unnegotiated format or claiming success.

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
  **Verified nonblocking TLS handshake increment at
  `fcd05f8e903a459ca85f13807bd35f7091f3fd70` (25 CTests):** the sole `PreauthConnectionStream` now drives one
  `SSL_do_handshake` attempt per readiness event, returns OpenSSL
  WANT_READ/WANT_WRITE distinctly, and binds the borrowed SSL pointer
  through retries. Complete X.224 Confirm output and server-role SSL
  are mandatory. Provider errors, null/client-role/wrong-pointer
  handles and cancellation fail closed; successful handshake reuses
  the same SSL for bounded encrypted MCS/GCC intake. The existing
  event-driven TCP adapter forwards `onTlsIoReady`, without
  installing a server listener. Two named test groups cover real
  in-memory TLS handshake progress through MCS and negative/replay
  gates. **NOT RUN:** exact-head CI, owner-local build, real connected
  socket TLS I/O, NLA/identity authentication, MCS Connect-Response
  and OS desktop admission.
  **PASS:** [Actions run 38566584099](https://github.com/k1moradi/RDP-server/actions/runs/38566584099)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy:
  both Debug/Release CTests, staged SDK installation, downstream
  consumer and three platform ZIP/SHA-256 artifacts. Ubuntu logs
  show **25/25 PASS** in Debug and Release.
  **NOT RUN:** owner's local post-change build, connected native
  TLS socket, independent credential/CredSSP/OS authorization,
  MCS Connect-Response or external RDP client/desktop.
  **Next:** drive the same TLS handshake over real connected
  nonblocking sockets in a safe loopback test, then authenticated
  RDP session establishment.
  **Verified native nonblocking loopback/TLS increment
  `7ce64737ccef439af2f0cfd383208181cc0e9513`
  (27 CTests):** a first-party OpenSSL custom BIO now borrows the
  existing `TcpNonblockingIo` and translates partial send/recv,
  would-block, EOF and I/O failure to OpenSSL readiness semantics
  without narrowing 64-bit Windows SOCKET handles. The existing
  `PreauthTcpAdapter` attaches this BIO only after the full X.224
  Confirm is sent; the same connection owner then drives
  `SSL_do_handshake` and bounded TLS MCS/GCC intake. Two new
  behavior-named CTests open ephemeral **127.0.0.1:0-only** TCP pairs,
  immediately close the temporary listener and verify native X.224,
  real TLS records carrying the Microsoft 416-byte MCS fixture,
  terminal EOF on a truncated CR and delivery of RDP_NEG_FAILURE.
  This is an isolated CI test, NOT installation/activation of a
  daemon or an externally reachable RDP server.
  **First CI FAIL:** [run 38578878083](https://github.com/k1moradi/RDP-server/actions/runs/38578878083)
  passed Ubuntu/GCC, Windows/MSVC and documentation-policy; on
  macOS/Clang two native loopback tests failed because the test
  assumed immediate recv readiness and immediate observation of TCP
  FIN. Corrected the **test driver only** to tolerate would-block
  and wait with bounded 1ms sleeps while retaining exact framing
  and terminal assertions.
  **PASS:** corrected [Actions run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
  on Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  both Debug/Release full **27/27 CTests** (confirmed in Ubuntu logs),
  installed SDK consumer and three ZIP/SHA-256 platform packages.
  **NOT RUN:** user's local build of the new code, external RDP
  clients, production certificate trust/enrollment, CredSSP/NLA,
  MCS Connect-Response, OS authorization and desktop.
  **Next:** authenticated session policy and the standards-compliant
  MCS server response.
  **Next protocol increment — T.125 MCS domain negotiation
  (pending exact-head CI):** the first-party
  `mergeMcsDomainParameters` implements Microsoft's
  [MS-RDPBCGR 3.3.5.3.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7617f746-95c9-4a6e-808d-e2f642471e86)
  eight-field target/minimum/maximum negotiation. The BER parser now
  allows min/max protocol versions other than 2 if they can negotiate
  version 2; the existing preauth diagnostic requires a successful
  merge, otherwise closes without MCS admission. Two NEW domain
  behavior tests cover the published Microsoft client fixture,
  each required fallback, unsupported version and all rejection
  branches. The four existing Connect-Initial test groups are
  individually registered without duplicating the executable:
  expected CTest total **32** (previously 27; two new behaviors,
  three additional registrations of existing behaviors).
  **PASS:** implementation `865c56c548526f4514207a4af1b192f3b3637c9a`
  in [CI 38582674975](https://github.com/k1moradi/RDP-server/actions/runs/38582674975):
  Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
  Debug/Release 32 CTests, installed downstream consumer and SDK
  ZIP/checksum gates. Owner-provided Linux Debug build and
  **32/32 CTest PASS** at the same code commit in the reused
  `~/rdp-server/build/` directory.
  **NOT RUN:** real external RDP client, CredSSP/NLA, authenticated
  OS admission or MCS Connect-Response emission.
  **Offline MCS Connect-Response encoder increment (CI pending;
  expected 34 CTests):** first-party
  `encodeMcsConnectResponse` constructs a bounded TPKT/X.224 Data TPDU,
  T.125 BER Connect-Response (APPLICATION 102), and T.124 GCC
  Conference Create Response with H.221 `McDn`. It emits
  `SC_CORE`, `SC_NET` with caller-provided, validated channel IDs,
  and `SC_SECURITY` with Enhanced TLS security values (0, 0)
  rather than a legacy RC4 certificate/random. DomainParameters
  come from the existing checked `mergeMcsDomainParameters` result.
  The encoder validates the actual client GCC settings, checks
  nodeID range 1001..65536, channel cardinality and uniqueness,
  requires the currently supported SSL offer (1), uses minimal BER
  and nonfragmented PER lengths, and returns no bytes on failure.
  **Offline only:** it does NOT send to a peer, register a domain,
  authorize credentials, or allocate a desktop or channel session.
  New `transport.mcs-response-wire` compares the whole 108-byte
  TLS-only response to an independently assembled oracle derived
  from [MS-RDPBCGR 4.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3);
  `transport.mcs-response-rejections` covers malformed or
  contradictory inputs and BER integer sign padding.
  **PASS:** implementation `e25cd3a05f46b7eaa2a259eb2da8ddb3b7459a87`
  passed Linux/GCC Debug/Release **34 CTests**, Windows/MSVC
  Debug/Release CTests, SDK consumer and packaging, and
  documentation-policy in [CI run 38586253181](https://github.com/k1moradi/RDP-server/actions/runs/38586253181).
  The owner's local Linux Debug `~/rdp-server/build/` run at
  `ddfc2d372285c397c52dca0197d30bf1c61c338e` confirmed
  **34/34 CTests PASS**; macOS status for that implementation is
  not independently asserted here.
  **NOT RUN:** production response emission, CredSSP/NLA user
  authentication, MCS domain lifecycle and desktop access.
  **Next:** implement bounded offline Erect/Attach/Join decoding,
  then authenticated connection admission and response ownership.
  **Offline MCS channel-connection request decoding (pending
  cross-platform CI; expected 37 CTests):** the portable
  `parseMcsChannelRequest` parses exactly one complete RFC1006
  TPKT/X.224 Data PDU holding T.125 aligned BASIC-PER
  ErectDomainRequest (subHeight/subInterval), AttachUserRequest or
  ChannelJoinRequest (initiator UserId and requested channel ID).
  It uses existing validated `parseDataTpdu` framing, bounded
  1..4-octet PER integers, canonical encodings and exact consumed
  lengths, and rejects wrong-direction PDU types, malformed padding,
  length mismatch, trailing bytes and UserId overflow. The
  initiator offset of 1001 is decoded **without** verifying that
  the account or channel exists. New CTests reuse the same MCS
  executable and Microsoft's 4.1.5/4.1.6/4.1.8 request examples:
  `transport.mcs-erect-request`,
  `transport.mcs-attach-request`,
  `transport.mcs-channel-join-request`.
  **Initial FAIL:** implementation `d5bc7d3b03906890da483dd1a480677a4fbaf73b`
  [CI run 38588334504](https://github.com/k1moradi/RDP-server/actions/runs/38588334504)
  failed Ubuntu Debug `transport.mcs-erect-request` at the
  *test-only* extended PER integer example: its octet length
  determinant claimed 4 bytes but the fixture provided 3.
  Other 36 CTests passed. The production parser correctly
  rejected the inconsistent packet. The test vector has been
  corrected from 0x04 to 0x03 without changing the decoder.
  **PASS:** corrected implementation
  `6effdb76229e2514511ebe5dd8cb404841403b1b`,
  [Actions run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy:
  both Debug/Release **37 CTests**, installed downstream SDK
  consumer, and three SDK ZIP/SHA-256 uploads. Ubuntu logs
  explicitly show **37/37 PASS** in both configurations.
  **PASS (owner-local):** the user's reused
  `~/rdp-server/build/` Linux Debug configure/build/CTest
  at `3135d66e557ecc8144fba02a8a69b5054b62ede9`
  passed **37/37**. This predates the new reply encoders.
  **NOT RUN:** TLS-verified domain phase admission, CredSSP/NLA,
  live attach/channel replies, OS authorization and desktop.
  **Next:** independent authenticated session authority and
  its single-owner MCS Attach/ChannelJoin lifecycle.
  **Offline Attach User and Channel Join confirmation encoding
  (2026-10-14; 39 CTests verified):**
  the existing portable `mcs_channel_connection.{h,cpp}` now
  constructs complete bounded TPKT/X.224/T.125 aligned-PER
  `rt-successful` Server Attach User Confirm and Channel Join Confirm
  packets without mutating session/domain/channel state.
  The assigned UserId must be 1001..65536 and is serialized
  as the 16-bit PER offset. A Channel Join Confirm requires a
  previously parsed Join request, the same explicitly assigned
  UserId, a nonzero requested channel, exactly one matching
  entry in a bounded externally supplied channel list, and
  correct repeated requested/confirmed ChannelId.
  Complete Microsoft example packets in MS-RDPBCGR 4.1.7
  (11 bytes) and 4.1.8.2.2 (15 bytes) are bytewise test oracles.
  Two new behavior CTests test successful encoding, both extrema
  of UserId, mismatched/duplicate/unallocated channels, wrong
  request kind and invalid identifiers. The library **does NOT**
  use these encoders to send packets; the supplied channel list
  does not prove OS identity, credential approval or MCS admission.
  **PASS:** implementation
  `4eb3bff4f9fc15cb72da1b8e994ec89e7e9a96db`,
  [Actions run 38590263498](https://github.com/k1moradi/RDP-server/actions/runs/38590263498)
  passed Linux/GCC, macOS/Clang, Windows/MSVC and
  documentation-policy, full Debug/Release CTests, installed SDK
  consumer and three ZIP/SHA-256 artifacts. Ubuntu logs confirmed
  **39/39 CTests PASS** in Debug and Release.
  **NOT RUN:** owner's updated local build, real CredSSP/NLA
  and OS-authorized session, encrypted live reply emission,
  external Microsoft clients and OS desktop.
  **Next:** implement a genuine CredSSP/NLA and independent OS
  identity authority, then let the sole server connection owner
  enforce MCS ordering, allocations and reply transmission.
- [ ] Implement TLS, CredSSP/NLA and independently verified OS session
  authorization, including security downgrade and failure tests.
  **CredSSP TSRequest decrypted-message framing increment (2026-10-14,
  46 CTests; exact-head CI PASS):** extend the existing
  first-party `credssp_tsrequest.{h,cpp}` with a fixed 16 KiB
  `TsRequestFrameReader`, preserving DER SEQUENCE/length boundaries
  across fragmented TLS application bytes, rejecting nonminimal,
  indefinite, oversized and unsupported DER lengths *before*
  large buffering, and leaving coalesced following-message bytes
  unconsumed. Completed bytes and SPNEGO/credential fields remain
  borrowed until explicit `releaseFrame()`; cancellation,
  malformed input and destruction wipe owned ciphertext via
  OpenSSL cleanse and terminate invalid frames. A second frame
  cannot overwrite an unreleased first frame. Three new
  behavior groups test every split, coalesced messages, DER
  0x81/0x82 lengths (including large bounded frames), invalid
  headers, EOF/cancellation and replay. Register the five
  prior CredSSP behavior groups separately without creating
  another executable (39 old registered CTests -> 46 expected).
  **This is syntax-only:** no SPNEGO acceptor, Kerberos/NTLM
  user authentication, version-5/6 TLS public-key binding,
  nonce validation, credentials decryption, OS account/session
  authorization, NLA X.224 negotiation or MCS admission is enabled.
  The existing diagnostic still selects only PROTOCOL_SSL and
  closes after MCS intake.
  **PASS:** implementation
  `c7f0463a3e11c8bd9fb6e8dfb404c3f1057d40cd`,
  [CI run 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy:
  Debug/Release full CTests, installed downstream SDK consumer
  and all three ZIP/checksum package artifacts. Ubuntu logs
  explicitly show **46/46 CTests PASS** in each build mode.
  **NOT RUN:** owner's local build of updated code,
  live CredSSP TSRequest TLS exchange, GSS/SPNEGO and
  independently authenticated OS session, external client
  or desktop acceptance.
  **Next:** connect this bounded DER handoff to a real
  CredSSP/SPNEGO provider and verified OS authorization in
  the sole connection owner; never treat a syntactically
  valid token as an authentication capability.
  **Verified bounded server-reply serialization (2026-10-14;
  48 CTests PASS):** within the same `credssp_tsrequest` module, an
  offline, allocation-bounded, canonical DER encoder produces
  one MS-CSSP TSRequest server `negoTokens` response OR an
  already-GSS-protected `pubKeyAuth` response for versions
  5/6. No credential or nonce output, TLS send, SPNEGO trust
  assertion or OS identity authority is added. Two additional
  existing-executable behavior CTests exercise literal DER wire
  oracles, lengths, parsing/framing and rejection bounds (expected
  **48 CTests**). **PASS:** exact implementation `46e77ed65afdd9526ee1c63d39724668670cf047`,
  [Actions run 38596955778](https://github.com/k1moradi/RDP-server/actions/runs/38596955778): 48/48 Debug and Release
  CTests on Linux/GCC, macOS/Clang and Windows/MSVC, SDK
  installed downstream consumer, all three ZIP/checksum
  uploads and documentation-policy gate. No prerelease tag.
  **NOT RUN:** owner's local build, real GSS/Kerberos,
  TLS public-key binding, OS admission or desktop.
  **Next:** connect to a trusted GSS provider and independent
  OS authorization before allowing any reply on a socket.
  **Verified Linux GSSAPI framed-token provider increment
  (2026-10-14; CI PASS):** compile the already-staged first-party
  MIT GSSAPI SPNEGO, public-key binding and deny-only credential
  sources behind explicit Linux-only `RDP_SERVER_TEST_LINUX_GSSAPI`.
  The existing GSS acceptor accepts a completed v5/v6 frame from
  `TsRequestFrameReader` synchronously, borrows only within
  the provider call and wipes the frame on return. Early,
  downgraded, malformed or GSS-rejected frames terminate both
  owners; an absent explicit keytab must never fall back to
  host credentials. The portable SDK has no mandatory GSSAPI
  dependency or newly enabled authentication path.
  **PASS:** implementation `36989cebcc6a69b51d1c3f3d5d1f2660417a9865`,
  [CI 38603782133](https://github.com/k1moradi/RDP-server/actions/runs/38603782133):
  Linux/GCC **50/50**, macOS/Clang and Windows/MSVC **48/48**
  CTests in both Debug and Release, SDK downstream consumer,
  three ZIP/checksum packages and documentation-policy. The two
  new Linux-only native GSS rejection suites passed.
  **NOT RUN:** owner-local updated build, live keytab/Kerberos
  credentials, positive GSS/TLS binding, OS admission, external
  client or desktop. **Next:** independently verify real
  configured provider credentials and TLS certificate binding,
  then implement independently authorized OS session admission
  before permitting live MCS responses.
  **Verified TLS->CredSSP frame intake increment (2026-10-14;
  CI PASS):** extend the existing 16 KiB `TsRequestFrameReader`
  with exactly one bounded `SSL_read_ex` per method call,
  pinning a finished server TLS identity, selected certificate,
  cipher and TLS >= 1.2. `Progress` requires immediate caller
  continuation for bytes already buffered inside OpenSSL;
  NeedRead/NeedWrite require actual transport readiness.
  Subsequent coalesced TSRequests remain unread until the
  first is released; reject SSL substitution, manual/TLS
  mixing, malformed DER and EOF terminally and wipe buffers.
  Reuse the existing OpenSSL memory-BIO fixture and add
  **three new** CTests for all fragment splits, coalesced
  envelopes and negative transport/mixed-source boundaries.
  **PASS:** implementation `d2885363502e34e52c71c41342902908b781fd58`,
  [CI 38607049062](https://github.com/k1moradi/RDP-server/actions/runs/38607049062):
  Linux/GCC 53/53, macOS/Clang 51/51 and Windows/MSVC
  51/51 CTests in both Debug and Release; all three
  new cases passed on each platform. SDK downstream
  consumer, ZIP/SHA256 artifacts and docs-policy PASS.
  **NOT RUN:** owner-local build, real GSS credentials,
  TLS CredSSP pubKeyAuth, OS-authorized admission or
  Microsoft desktop connection. The diagnostic remains
  PROTOCOL_SSL and never grants identity. **Next:**
  authenticated GSS binding to the selected TLS
  certificate and independent OS authorization before
  any MCS response or remote desktop admission.
  **Verified TLS-owned GSS provider provenance increment
  (2026-10-14; CI PASS):** MS-CSSP 2.2.1/3.1.5
  requires SPNEGO and encrypted public-key validation
  in the same TLS session. The one `TsRequestFrameReader`
  now exposes server-SSL provenance only for a complete
  TLS-read frame, never synthetic/partial/released DER.
  The Linux `GssapiSpnegoAcceptor` requires this evidence,
  pins the SSL pointer and v5/v6 version across framed
  negotiation, rejects mismatched SSL/version, and
  checks the pinned identity and version again before
  protected-binding GSS unwrap. Rejection erases
  borrowed identity without creating extra buffers
  or granting account/session authority.
  **PASS:** implementation `6e11b25224e1a5e6c3f45778436afc3950a3e866`,
  [CI 38609620612](https://github.com/k1moradi/RDP-server/actions/runs/38609620612):
  Linux/GCC **55/55**, macOS/Clang and Windows/MSVC
  **52/52** CTests in BOTH Debug and Release. Two
  new behavior-named tests (portable TLS provenance
  and Linux-only real-provider fail-closed handoff)
  passed. SDK downstream consumer, three ZIP/checksum
  uploads and documentation-policy also PASS.
  **NOT RUN:** owner's local updated build, real keytab
  or Kerberos tickets, positive GSS context, TLS
  public-key proof, OS authorization, Microsoft client
  and desktop. **Next:** genuine positive Kerberos/GSS
  with selected TLS certificate and interoperable
  MS-CSSP final negoToken+pubKeyAuth phase, followed
  by independent OS authorization before MCS admission.
  **Verified MS-CSSP final combined token/binding processing
  (2026-10-14; CI PASS):** Microsoft's
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  requires the last client SPNEGO token and encrypted TLS
  public-key binding together in one TSRequest. The
  first-party v5/v6 framer validates exactly one token,
  encrypted pubKeyAuth, a 32-byte nonce and no authInfo
  or errorCode. The optional Linux GSSAPI provider requires
  a continuing context and pinned SSL/version, accepts
  the final token and demands fully verified Kerberos
  security flags; it rejects a GSS output token that
  cannot be sent in the binding-only server reply,
  then uses confidential GSS unwrap/wrap and the selected
  active TLS certificate to generate a protected reply
  before securely releasing the frame. This is NOT a
  successful Kerberos exchange or desktop admission.
  **PASS:** implementation
  `ad848646391eb7f2dce5c8e2a6238212e7f4e5ae`,
  [CI 38612269453](https://github.com/k1moradi/RDP-server/actions/runs/38612269453):
  Linux/GCC **58/58**, macOS/Clang and Windows/MSVC
  **54/54** CTests in both Debug and Release, including
  all THREE newly registered behavior-named cases.
  SDK install/downstream consumer, ZIP+SHA-256 artifact
  uploads and documentation policy PASS across all systems.
  **NOT RUN:** owner's local new build, positive real GSS
  credentials/keytab, actual TLS pubKeyAuth validation,
  external Microsoft clients, independent OS account
  authorization or real desktop. **Next:** controlled
  positive real GSS/Kerberos and binding interoperability,
  then independent OS authorization before any MCS
  domain replies or desktop activation.
  **Verified bounded TLS server TSRequest reply transport
  (2026-10-14; CI PASS):** per
  [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
  the existing first-party `credssp_tsrequest` module
  now writes one bounded canonical server negoToken
  or GSS-protected pubKeyAuth DER reply over pinned
  finished server TLS. It retains a stable, owned
  byte buffer across OpenSSL WANT_READ/WANT_WRITE,
  never counts unsuccessful writes, prohibits
  conflicting TLS identities or overlapping records,
  and wipes sensitive contents on release/cancel.
  This is transport only: no SPNEGO provider success,
  trusted user identity, OS authorization, NLA
  activation, positive MCS reply or desktop.
  Three NEW behavior-named CTests use real OpenSSL
  memory BIO TLS, including exact wire, WANT_WRITE
  backpressure/retry and terminal error denial.
  **Initial FAIL:** implementation
  `915cd2bfac59d7e775b458b7deed3d94db17ad93`,
  [CI 38614500856](https://github.com/k1moradi/RDP-server/actions/runs/38614500856):
  the backpressure fixture attempted unsupported
  `BIO_set_write_buf_size` on an already paired
  memory BIO; this was test setup failure.
  **PASS:** corrected fixture implementation
  `afa7d737b4ee32c0f0e72bbedd32e6cb9066afd6`,
  [CI 38614808824](https://github.com/k1moradi/RDP-server/actions/runs/38614808824):
  Linux/GCC **61/61**, macOS/Clang and Windows/MSVC
  **57/57** CTests in BOTH Debug and Release,
  including all three new cases, SDK downstream
  consumers, three ZIP/SHA-256 artifact uploads
  and policy gate. Constrained server BIO capacity
  is now established before handshake with no
  weakened assertions. Preexisting Linux Release
  test fixture compiler warning remains nonfatal.
  **NOT RUN:** owner-local new build, real positive
  GSS/Kerberos ticket/keytab and public-key binding,
  OS identity authorization, external RDP client
  or desktop. **Next:** connect the verified transport
  to a real provider-generated GSS exchange, verify
  TLS pubKeyAuth end to end, and independently
  authorize OS session access before any MCS reply.
  **Verified Linux real-GSS-to-TLS server reply handoff
  (2026-10-14; CI PASS):** per Microsoft
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
  the existing optional real MIT GSS provider
  can now queue its own SPNEGO continuation
  `negoTokens` or confidentially wrapped final
  server `pubKeyAuth` on the original server
  TLS, using the existing bounded nonblocking
  `TsRequestTlsReplyWriter`. The handshake
  requires a real provider output, correct
  stage/version, matching SSL frame provenance,
  idle outgoing writer, and successful final
  client GSS/TLS certificate-bound proof.
  Transient GSS output is cleansed immediately
  after queueing; reject closes all three
  owners. This helper does NOT itself send
  TLS, enable NLA, authorize an OS user,
  generate MCS responses or admit a desktop.
  **PASS:** implementation
  `27e8342aee0e475c3b0854330678e7c7596fc912`,
  [CI 38617602493](https://github.com/k1moradi/RDP-server/actions/runs/38617602493):
  Linux/GCC **64/64** CTests in BOTH Debug
  and Release (all **three NEW** GSS-TLS
  provider response-gate tests PASS),
  macOS/Clang and Windows/MSVC **57/57**
  each in Debug and Release, documentation
  policy PASS, three SDK downstream
  consumers, ZIP/SHA256 package uploads PASS.
  The new tests use actual TLS application
  records and real linked MIT GSSAPI, but
  deliberately assert negative results
  WITHOUT installed Kerberos credentials.
  A preexisting unrelated Linux Release
  `-Wstringop-overflow` in test fixture
  `tests/test_owned_preauth_session.cpp:589`
  remains nonfatal.
  **NOT RUN:** owner-local update build,
  genuine positive keytab/ticket mutual
  Kerberos exchange, live selected-TLS
  pubKeyAuth verification, independently
  authorized OS account/session, external
  Microsoft RDP clients or desktop.
  **Next:** controlled opt-in positive
  Kerberos/GSS+TLS public-key binding,
  then independently checked OS policy and
  single-owner live X.224/MCS transitions.
  **Verified active server TLS certificate identity pin and
  real TLS binding (2026-10-14; CI PASS):** Microsoft
  [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  bind the client/server proof to the selected TLS
  certificate SubjectPublicKey, 32-byte nonce and
  distinct direction labels. The existing one
  `TsRequestFrameReader` now pins the selected
  server X.509 SHA-256 fingerprint as well as
  `SSL*` on its FIRST real TLS read. It checks
  both before later TLS chunks, after frame
  completion and after release: even a different
  selected certificate on the SAME SSL pointer
  revokes handoff and closes/wipes the frame.
  The existing `credssp_tls_certificate`
  module owns finished TLS >=1.2 server-role/
  cipher/cert checks and active certificate
  SubjectPublicKey hashing, without GSS or
  OS session authority. Three new portable
  CTests use real in-memory OpenSSL TLS, comparing
  both direction-specific live-certificate hashes
  with independent SubjectPublicKey calculations;
  reject other certs, nonces, reflected/mutated
  hashes and invalid TLS roles; and reject
  completed/partial DER after same-SSL cert
  replacement while accepting unchanged identity.
  **Initial FAIL:** implementation
  `d0583c92eb6b6a3517d5e96ea5fd8adc07ee413d`,
  [CI 38619291326](https://github.com/k1moradi/RDP-server/actions/runs/38619291326):
  new test compile failed due to OpenSSL 4-compatible
  `const X509*` source passed to `SSL_use_certificate`.
  **PASS:** correction
  `340ce518d0e84ea94a4d24c295f8fa88e74ccf6d`
  duplicates the test-only certificate with
  `X509_dup` into existing RAII `CertificatePointer`
  and retains all assertions.
  [CI 38619544190](https://github.com/k1moradi/RDP-server/actions/runs/38619544190):
  Linux/GCC **67/67** and macOS/Clang,
  Windows/MSVC **60/60** CTests, BOTH Debug
  and Release; three new cases, installed
  SDK consumers, ZIP/SHA256 uploads,
  documentation-policy PASS. Prior Linux
  Release fixture warning remains nonfatal.
  **NOT RUN:** owner-local new build, positive
  actual Kerberos/GSS service keytab/tickets,
  true GSS unwrap/wrap TLS public-key proof,
  independent OS account authorization,
  Microsoft client or real desktop.
  **Next:** positive controlled Kerberos/GSS
  and TLS binding, then independent OS policy
  before admitting real MCS/desktop.
  **Verified TLS-framed GSS binding-only provenance boundary
  (2026-10-14; CI PASS):** Microsoft
  [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  require real SPNEGO and encrypted public-key
  proof inside the original established TLS
  transcript. The Linux acceptor's historical
  `processProtectedBinding(SSL*, rawDer)` is
  now permanently deny-only: raw caller-supplied
  bytes, even with an SSL pointer and an
  otherwise authenticated provider, never
  prove TLS record provenance.
  `processFramedProtectedBinding(reader)`
  requires exactly one complete TLS-derived
  v5/v6 binding-only DER frame, unchanged
  pinned SSL/selected X.509 certificate and
  negotiation version, with successful REAL
  GSS context and confidential unwrap before
  nonce/hash comparison and protected server
  response. The existing combined-final and
  new binding-only queue methods now share
  one guarded idle-writer handoff; terminal
  failure closes reader, provider and writer.
  **PASS:** implementation
  `340b25d2352314003053ec19d467b75d578c9dbf`,
  [CI 38623829568](https://github.com/k1moradi/RDP-server/actions/runs/38623829568):
  Linux/GCC **69/69** and macOS/Clang,
  Windows/MSVC **60/60** CTests in BOTH
  Debug and Release; TWO new Linux real
  TLS/GSS-linked denial and outgoing-order
  CTests passed, along with all previous
  regression groups, staged SDK/consumer,
  ZIP/SHA-256 uploads and documentation
  policy. The previously existing Linux
  Release test fixture warning remains
  nonfatal. These tests are **negative-only**
  for GSS authentication. No positive ticket,
  keytab, GSS unwrap success, independently
  authorized OS account, Windows App client
  or real desktop was run.
  **Next:** opt-in controlled genuine positive
  Kerberos/GSS exchange with explicit test
  keytab/client ticket and active TLS binding,
  then independent OS authorization before
  any live MCS/desktop admission.
  **Verified outgoing CredSSP TLS reply certificate continuity
  (2026-10-14; CI PASS):** per Microsoft's
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
  every canonical v5/v6 `TSRequest` reply must
  remain tied to the actual server TLS-selected
  X.509 public key. The existing
  `TsRequestTlsReplyWriter` now pins one SHA-256
  fingerprint of the selected finished server
  certificate at its FIRST reply queue, in
  addition to its one `SSL*` identity.
  On EVERY subsequent SSL_write_ex readiness
  retry, idempotent Complete, reply release
  and next reply queue it rechecks the
  selected certificate in constant time
  with the existing first-party certificate
  helper. A changed selected certificate
  on the SAME SSL pointer fails terminally,
  closes and wipes pending DER/fingerprint
  BEFORE a new TLS write. Previously emitted
  TLS ciphertext cannot be retroactively
  recalled. No duplicate state controller
  or output encoder was added.
  Three NEW all-platform real TLS CTests
  cover v5/v6 SPNEGO and pubKeyAuth replies
  denied before write with zero delivered
  plaintext after certificate replacement;
  changed certificate after Complete,
  before release and after release, with
  unchanged positive multi-reply reuse;
  and a real 2048-byte memory-BIO
  SSL_ERROR_WANT_WRITE followed by same-SSL
  certificate mutation and no retry.
  **PASS:** implementation
  `53184c7e4fdfb1c01f287933ff4ca0a6fdf63c0a`,
  [CI 38674532102](https://github.com/k1moradi/RDP-server/actions/runs/38674532102):
  Linux/GCC **72/72**, macOS/Clang
  and Windows/MSVC **63/63** CTests
  in BOTH Debug and Release; all three
  new cases, documentation policy,
  installed SDK downstream consumer
  and all three ZIP/SHA256 package
  uploads PASSED. Previous unrelated
  nonfatal Ubuntu Release test fixture
  `-Wstringop-overflow` remains.
  **NOT RUN:** owner's local build,
  positive real service-keytab/client-ticket
  Kerberos/GSS and confidential
  active-TLS pubKeyAuth, independently
  authorized OS account/session,
  Windows App or actual desktop.
  **Next:** explicitly authorized
  controlled genuine Kerberos/SPNEGO
  and active TLS certificate binding,
  then independently audited OS policy
  before any MCS/session admission.
  **Verified Linux GSS acceptor transcript-wide TLS certificate pin,
  with unrun opt-in genuine Kerberos probe (2026-10-14):** per
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  and [RFC 4178](https://www.rfc-editor.org/rfc/rfc4178.html),
  the existing Linux MIT GSS provider now pins the first
  selected server TLS X.509 DER SHA-256 fingerprint inside
  the acceptor itself, IN ADDITION to its original SSL*
  and CredSSP v5/v6 version. Every later TLS-framed
  SPNEGO request, binding-only or combined-final proof,
  confidential GSS hash check and queued server
  binding response rechecks the exact selected certificate,
  even if the caller replaces the frame reader between
  rounds on the SAME SSL*. Terminal reject cleanses
  the fingerprint and authenticated principal and
  closes the GSS context and explicit credentials.
  No new session controller or OS account authority.

  One separately gated Linux-only acceptance probe
  is compiled into the original TLS fixture and
  registered ONLY under `RDP_SERVER_TEST_REAL_KERBEROS=ON`
  with an explicitly supplied `TERMSRV/host@REALM`,
  `FILE:/` service keytab and separate `FILE:/`
  client ticket cache. It invokes real MIT
  GSS initiator/acceptor through TLS application
  records, GSS-confidential v5/v6 binding-only
  verification, and a new-reader, SAME-SSL
  X.509 swap rejection. No KDC or desktop is started;
  no default host keytab/cache or client credential
  contents are imported into the project.
  Binding-only proof is an internal diagnostic,
  NOT normative combined-last-token MS-CSSP
  interoperability or independently authorized
  account/session acceptance.

  **PASS:** implementation
  `1f6740452f27332303ded71d4f5f23bb599b9726`,
  [CI 38678010820](https://github.com/k1moradi/RDP-server/actions/runs/38678010820):
  Linux/GCC **72/72** and macOS/Clang,
  Windows/MSVC **63/63** standard CTests,
  EACH Debug and Release, three installed SDK
  downstream consumers, ZIP/SHA256 package
  uploads and documentation-policy PASS.
  The Linux test executable compiles the new
  GSS probe code, but the opt-in case was
  NOT registered or executed with CI credentials.
  Existing Ubuntu Release nonfatal
  `-Wstringop-overflow` at TLS fixture
  line 594 remains.
  **NOT RUN:** actual positive keytab/client
  ticket authenticated GSS handshake,
  GSS-confidential pubKeyAuth probe,
  real Microsoft combined-final client,
  owner's local build, independent OS
  authorization, live RDP server or desktop.
  **Next:** with explicit authority and
  isolated real ticket/keytab, RUN the
  opt-in positive provider/TLS-binding probe
  and close any MS-CSSP combined-last-token
  interoperability gaps before independent
  OS session admission.
  **Partial real-provider CredSSP v6 SPNEGO failure dispatch
  (2026-10-15; CI PASS):** the existing
  Linux MIT GSS acceptor now marks a provider/policy
  rejection only when the configured, explicit-keytab
  `gss_accept_sec_context` was actually called on a
  TLS-derived and valid SPNEGO negotiation request.
  For version 6 ONLY, recheck the original SSL and
  selected X509 SHA256 fingerprint after GSS terminal
  cleanup; then enqueue fixed `STATUS_LOGON_FAILURE`
  using the existing single 15-byte DER error encoder
  and nonblocking `TsRequestTlsReplyWriter`.
  `SpnegoStatus::FailureQueued` means error queued,
  GSS credentials/principal already wiped, but NO
  SSL record written or authenticated session.
  Missing keytab, invalid DER/token, wrong/changed TLS,
  version 5, failed local memory or pending writer
  MUST silently terminate, not synthesize GSS denial.
  Extend original preauth TLS fixture with one default
  Linux GSS-only negative CTest, and a separately
  registered opt-in genuine MIT rejection + TLS
  15-byte error oracle (requires explicitly authorized
  service keytab and ticket cache). Default CTest
  counts: **77 portable / 87 Linux GSS** (prior 77/86);
  opt-in positive credentials and failure delivery
  still **NOT RUN** without owner authorization.
  Baseline `ebc794738552f5411ebe4d2222000f8ae94183f2`,
  [Actions 38708915869](https://github.com/k1moradi/RDP-server/actions/runs/38708915869)
  PASS; owner reports **77/77** local on prior main.
  **PASS:** implementation `b4c9f8eff73e701130cc8b92b6c1fda50aedcf11`,
  [Actions 38710937644](https://github.com/k1moradi/RDP-server/actions/runs/38710937644):
  Linux/GCC **87/87**, macOS/Clang and Windows/MSVC
  **77/77** full CTests in EACH Debug and Release,
  including new Linux GSS fail-closed behavior;
  installed SDK downstream consumer, ZIP/SHA256
  artifacts and documentation policy PASS.
  Prerelease publication SKIPPED (no release tag).
  **NOT RUN:** owner-local incremental compile/CTest,
  opt-in configured real GSS rejection/errorCode
  delivery, full Microsoft combined-last-token,
  OS admission, real RDP client or desktop.
  **Next:** owner explicitly provisions
  isolated real Kerberos keytab and client tickets
  before opt-in provider/TLS proof and independent
  OS authorization, then the one live CredSSP owner
  can govern a complete authenticated negotiation.
  **Verified version-6 CredSSP errorCode server reply transport
  (2026-10-14; CI PASS):** [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  specify a server `TSRequest.errorCode`
  on failed SPNEGO at protocol versions
  3/4/6. The current v5/v6-only native
  reply codec now supports ONLY a
  version-**6** negative NTSTATUS
  failure record. It emits exact
  15-byte DER with [0] version and
  [4] signed 32-bit failure: the fixed
  `STATUS_LOGON_FAILURE` (0xC000006D)
  or `STATUS_NOT_SUPPORTED` (0xC00000BB).
  It rejects v5/legacy versions,
  unknown codes, mixed SPNEGO/pubKeyAuth/
  authInfo/nonce fields and any success
  status. The existing, single
  `TsRequestTlsReplyWriter` queues
  canonical negotiated tokens, sealed
  bindings, and failures through ONE
  private encoder-owned guarded queue.
  It retains TLS SSL*/selected X509
  fingerprint, nonblocking retry
  pointer, one-pending-response limit,
  and wipe-on-error. A completed
  failure is released to CLOSED,
  never followed by a success response.
  FOUR new portable behavior cases
  check exact independent DER oracles,
  rejected versions/fields/nonminimal
  signed integer, real TLS delivery
  and terminal failure behavior, and
  pending-reply/wrong-TLS/same-SSL
  certificate-swap rejection.
  **PASS:** implementation
  `6925ac11a49b3d71a6ffa120b688ca95a0a088af`,
  [CI 38683205424](https://github.com/k1moradi/RDP-server/actions/runs/38683205424):
  Linux/GCC **76/76**, macOS/Clang
  and Windows/MSVC **67/67** CTests
  in BOTH Debug and Release,
  ALL four new tests PASSED on
  all three OS, installed SDK
  consumer, ZIP/SHA256 packages
  uploaded and docs policy passed.
  The earlier unrelated nonfatal
  Ubuntu Release `-Wstringop-overflow`
  in `test_owned_preauth_session.cpp:594`
  persists.
  **NOT RUN:** owner's local build,
  opt-in successful real Kerberos
  service keytab and client ticket,
  automatic server GSS failure
  dispatch to this optional message,
  authenticated TLS public-key
  binding, independent OS session
  policy, Microsoft RDP client
  or usable desktop.
  **Next:** controlled opt-in
  real Kerberos/GSS and active-TLS
  binding proof; when authorized,
  wire terminal failure response
  to explicit GSS state without
  promoting it to authentication
  success; independent OS admission
  before real MCS or desktop.
  **Verified bounded DER intake hardening (CI PASS):**
  reorder the existing CredSSP first-tag check before the
  end-of-input NeedMore return so a single wrong tag byte
  immediately closes the frame owner; a valid single 0x30
  byte continues waiting for the length. The existing
  `security.credssp-stream-rejections` CTest exhausts
  all 255 invalid first tags, exact consumption, irreversible
  close and the valid-prefix control. Based on prior main
  `1cce799dc1aa7a55e3cb343dd09823052a1c23a6`.
  **PASS:** implementation `36926462d34726f355279367a2ba2f27e93d2095`,
  [CI 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429)
  Linux/GCC, macOS/Clang, Windows/MSVC full Debug/Release,
  documentation-policy and SDK/package gates. The owner also
  provided a single-build-root Linux Debug **67/67 PASS** log
  on that exact commit. Real credentials, external clients and
  desktop acceptance remain NOT RUN.
  **Next:**
  continue explicit authenticated GSS/OS admission gates
  separately; no external-client/desktop acceptance claimed.
- [ ] Implement licensing, capabilities/share activation, virtual-channel
  routing, graphics delivery, keyboard/pointer and correct lifecycle.
  **Verified partial offline MCS lifecycle boundary (CI PASS):**
  the existing `mcs_channel_connection` parser now recognizes
  strictly framed Disconnect Provider Ultimatum with ignored
  inbound reason; the allocation-free server serializer emits
  only provider-initiated (1) or user-requested (3) as required
  by MS-RDPBCGR 2.2.2.3 / 3.1.5.1.1. Two additional portable
  CTests exercise the published nine-byte example and exhaustive
  invalid reason/truncation/transport cases. Baseline main
  `36926462d34726f355279367a2ba2f27e93d2095`
  had owner's Linux Debug **67/67 PASS** and
  [CI 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429)
  PASS. **PASS:** implementation `ed4b0c0a05981f573bc6b8369893f33d1e71549d`,
  [CI 38685111404](https://github.com/k1moradi/RDP-server/actions/runs/38685111404):
  Linux/GCC **78/78** and macOS/Clang, Windows/MSVC **69/69**
  in EACH Debug and Release, including both new disconnect cases,
  installed SDK consumers, three ZIP/SHA-256 archives and
  documentation-policy. The prerelease publishing job was SKIPPED
  (no version tag). Owner-local tests of this **new** commit are
  NOT RUN. This is NOT an authenticated server or live teardown.
  **Next:** build the one authenticated session state machine
  with controlled GSS/Kerberos and independent OS admission;
  only then verify TLS-encrypted disconnect send completion
  followed by socket close.
  **Partial offline client SendDataRequest framing (CI NOT RUN):**
  the existing `mcs_channel_connection` parser recognizes T.125
  client DomainMCSPDU choice 25 (0x64), initiator offset from
  1001, channel, priority, segmentation and bounded 7-bit/14-bit
  PER OCTET STRING length. It returns a borrowed caller-buffer
  span without heap copies; malformed lengths, unsupported
  PER fragmentation, invalid padding, bad TPKT and initiator
  overflow fail closed. Two extra portable behavior CTests
  reuse the original MCS executable (71 portable / 80 with
  Linux GSSAPI expected). Baseline main
  `05f2708cc8b326983c406b643bee1d47e5e166d0`
  passed [CI 38685374294](https://github.com/k1moradi/RDP-server/actions/runs/38685374294)
  and the owner reports 69/69 local CTests PASS.
  **First CI FAIL** for implementation
  `c1f9e5458132c40b149e8ec5f0e6083addff8715`:
  [run 38696231297](https://github.com/k1moradi/RDP-server/actions/runs/38696231297)
  found an invalid *test* lifetime: parsing a temporary
  `frameDomainPdu` and reading its borrowed `userData`
  after the vector was destroyed. Linux Debug **79/80**
  and macOS Debug **70/71** passed; the sole failed case
  was `transport.mcs-send-data-wire`. Follow-up keeps
  that frame alive through all view assertions without
  changing the production parser, and adds an offset check.
  **PASS:** correction
  `72af29fddc2424fcc7f4edbd579e2b313ef25f48`,
  [CI 38696503496](https://github.com/k1moradi/RDP-server/actions/runs/38696503496):
  Linux/GCC **80/80**, macOS/Clang and Windows/MSVC
  **71/71** CTests in BOTH Debug and Release; both new
  SendData wire/negative cases, documentation-policy,
  installed SDK consumer and three ZIP/SHA256 packages
  PASS. Prerelease publication SKIPPED (no release tag).
  Owner-local test of the corrected exact commit NOT RUN.
  This does not enable live TLS MCS intake, authorized channel
  membership, reassembly or desktop session admission.
  **Next:** run exact-head full CI; then controlled real
  Kerberos/GSS transcript, verified OS identity/session
  policy, and one owner for all post-auth channel states
  before delivering any client Send Data payload.
  **Partial offline server SendDataIndication encoding (2026-10-15;
  CI NOT RUN at authoring):** the existing first-party MCS
  module can now serialize server-to-client T.125 DomainMCSPDU
  choice 26 to a caller-owned contiguous buffer, with checked
  UserId/channel, priority, segmentation and canonical
  unfragmented PER payload length up to 16383 bytes.
  The result is fixed-header plus one overlap-safe memory
  move, no internal allocation; reject invalid parameters
  or insufficient capacity without mutating output.
  Two additional tests (73 portable / 82 Linux GSS-enabled
  expected) cover byte-exact wire, length boundaries,
  aliasing, bounds and fail-closed output.
  Baseline parent `cd50346be4df281b7fc207c5126072555a3eba63`
  passed [CI 38696744690](https://github.com/k1moradi/RDP-server/actions/runs/38696744690);
  owner reports local **71/71 PASS** on prior code.
  **PASS:** implementation `8c9fabeb02fce7ede13abfb42631d3b7f35a4fc1`,
  [Actions run 38701524465](https://github.com/k1moradi/RDP-server/actions/runs/38701524465):
  Linux/GCC **82/82**, macOS/Clang and Windows/MSVC
  **73/73** CTests in BOTH Debug and Release, including
  both new cases; SDK install/downstream consumer,
  ZIP+SHA256 uploads and documentation policy PASS.
  Prerelease publishing SKIPPED (no release tag).
  **NOT RUN:** owner's local build of this new commit,
  independent OS admission, joined-channel enforcement,
  actual TLS sends, real client, licensing, graphics or desktop.
  **Next:** exact-head cross-platform CI; then controlled
  true GSS/Kerberos/TLS identity and separate OS policy
  before wiring any SendData indication into the one
  authorized session owner.
  **Verified partial offline Share Control Header decoder (2026-10-15;
  CI PASS):** extend the original C++23
  MCS module with a strict, zero-copy T.128
  `TS_SHARECONTROLHEADER` decoder per MS-RDPBCGR
  2.2.8.1.1.1.1. It checks six-byte LE framing,
  complete declared length, version 1 and all five
  documented PDU types, but no nested data message.
  Recognize `totalLength=0x8000` as a MUST-IGNORE
  FlowPDU without exposing body or accepting it as
  activation. Reuse the existing test executable for
  Microsoft 26-byte Control PDU and malformed/ignored
  cases; expected **75** portable and **84** Linux
  GSS-enabled CTests (73 and 82 prior). Baseline main
  `424a35a8ceeb2a32fc553f334cfdcdfeebf5e2a6`
  passed [Actions 38701851845](https://github.com/k1moradi/RDP-server/actions/runs/38701851845);
  owner reports **73/73 local PASS** on that prior code.
  **PASS:** implementation `77fd1be92c0f4dcff60962d645a39af9b23c96de`,
  [Actions 38705203733](https://github.com/k1moradi/RDP-server/actions/runs/38705203733):
  Linux/GCC **84/84**, macOS/Clang and Windows/MSVC
  **75/75** full CTests in BOTH Debug and Release;
  new Share Control cases, documentation-policy,
  installed SDK consumer and all three ZIP/SHA256
  artifacts PASS. Prerelease publishing SKIPPED
  without a version tag.
  **NOT RUN:** owner-local new compile, actual Share
  Control/Share Data dispatch, optional security-header
  handling, licensing, independent MCS/OS authorization,
  external Windows App or desktop session.
  **Next:** genuine authorized GSS
  with active TLS proof, independent OS session policy,
  and the sole authenticated owner for licensing/share
  activation and nested PDU processing.
  **Verified offline T.128 Share Data Header decoding (2026-10-15;
  CI PASS):** reuse the existing MCS/Share
  Control module to decode the 12-byte Share Data Header only
  after an explicitly isolated, complete Data PDU. Accept the
  24 normative type2 values, stream priorities 1/2/4, and
  stream 0 ONLY with Synchronize for known server behavior;
  ignore pad1; preserve uncompressedLength and compressedLength
  as metadata, never allocation or trust boundaries.
  Reject any compressedType != 0 pending real negotiated
  decompression, or any truncated/unknown/FlowPDU input,
  without exposing a borrowed application payload.
  Two behavior-named regression tests reuse the original
  MCS executable with 3 real Microsoft sample layouts;
  **77** portable and **86** Linux GSS-enabled CTests
  expected (75 and 84 prior).
  Baseline `8aea09a101fe1394c6c60145fef42fa002514315`
  passed [CI 38705731398](https://github.com/k1moradi/RDP-server/actions/runs/38705731398);
  owner reports **75/75 local PASS** on that prior main.
  **PASS:** exact implementation `9bc9e041419b4a932dc988a51f1f3e920ac82ba3`,
  [CI 38708579033](https://github.com/k1moradi/RDP-server/actions/runs/38708579033):
  Linux/GCC **86/86**, macOS/Clang and Windows/MSVC
  **77/77** full CTests in EACH Debug and Release;
  both new Share Data groups, project policy, staged
  installed SDK consumer and three ZIP/SHA256 artifacts
  PASS. Prerelease publication SKIPPED (no version tag).
  **NOT RUN:** owner-local NEW compile/CTest, independently
  authenticated OS/session, live TLS/ShareData routing,
  negotiated decompression, licensing, client activation,
  input or desktop.
  **Next:** authorized
  opt-in genuine GSS/Kerberos + TLS certificate binding,
  independent OS session admission, and only afterward
  single-owner Share Control/Share Data lifecycle.
- [ ] Deliver the **first usable, H.264-only Microsoft-compatible RDP server**:
  implement RDPGFX/DVC lifecycle, AVC420 capability selection, surface mapping,
  changed-region encoding, reference-frame correctness, frame ACK flow control,
  resizing and reconnects together with authorized desktop capture/input.
  Reuse existing first-party C++23 dirty-tile/fingerprint/NV12 scheduling;
  permit native RDPGFX fills, copies and cache reuse (not additional codecs).
  **Use x264 as the sole initial software H.264 encoder:** build a pinned,
  license-reviewed static x264 library (without its CLI/FFmpeg) within the one
  reused build root and link it into the future server executable through a
  small C++23 RAII wrapper. Verify static-link feasibility on Linux/GCC,
  macOS/Clang and Windows/MSVC; keep the current standalone protocol SDK
  independent of encoder dependencies until the runtime is implemented.
  Give one owner exclusive encoder access and lifetime, validate NV12 strides
  and dimensions, and preserve NAL output until packetization. x264 encodes
  complete H.264 pictures even when capture/conversion and RDPGFX updates
  are dirty-region-aware; preserve reference continuity across submissions.
  Defer ClearCodec, Planar and RemoteFX compression entirely; AVC444/v2 is a
  later H.264-only option **only if client negotiation or text fidelity requires
  it**. Never advertise an unsupported mode or silently fall back when AVC420
  is unavailable. **Status: NOT RUN / not a working RDP server.**
- [ ] Confirm H.264 capability negotiation and a genuinely interactive,
  authenticated desktop with current Windows App on Windows/macOS and
  Windows 11 Remote Desktop Connection. Record actual versions, advertised
  capability sets and failures (including AVC disabled/missing), then verify
  text/input, scrolling, menus, images, clipboard, display resize, frame
  ordering and reconnect. **Status: NOT RUN; no real-client acceptance yet.**

### P1 — Real client features and performance

- [ ] **One native CLIPRDR clipboard session owner** (MS-RDPECLIP): reuse
  `src/server/clipboard/remote_transfer.*`, existing first-party PDU/PNG/DIB
  helpers and tests. Implement channel/capability negotiation, long/short
  named format mapping, Format List acknowledgment, Unicode text, PNG and
  DIBV5/DIB requests/responses, bounded reassembly and cancellation.
  Ordinary Format Data Responses have **no request ID**: permit only one
  outstanding format-data request, associate it with the advertised generation,
  drain obsolete replies, and fail closed on irrecoverably ambiguous timeout.
  File-content replies have separate `streamId` correlation. Do not create
  competing session controllers or depend on xrdp/FreeRDP at runtime.
  **Status: NOT RUN; native channel/desktop integration not implemented.**
- [ ] **Bounded eager text/image retrieval, with delayed OS presentation**:
  after a *legitimate client Format List* for generation N, prioritize
  `CF_UNICODETEXT` and registered `PNG` (look up names, not fixed IDs),
  falling back to `CF_DIBV5`/`CF_DIB` when PNG is unavailable. Serialize
  prefetch over the one-at-a-time format-data channel without starving an
  actual paste. Maintain advertised/requested/receiving/ready/failed state;
  cache only verified, size-limited UTF-8 text and compressed image bytes
  for the current generation. Decode/convert on demand with checked image
  dimensions and bounded worker resources; avoid unconditional expanded
  bitmap copies. Never publish incomplete, corrupt or superseded content.
  Client OS focus/privacy policy may delay or suppress an announcement:
  do not poll, infer unseen copies or bypass the client's policy.
  **Status: NOT RUN; screenshot/text prefetch and conversion unimplemented.**
- [ ] **Nonblocking clipboard paste readiness**: register a pending OS paste
  request and deadline; process RDP/desktop events while remote transfer or
  image conversion completes, then satisfy the *same* request or reject on
  timeout, disconnect, clipboard replacement or owner loss. Do not call
  `sleep_for` or wait on a condition variable in the event loop. Support
  X11 asynchronous SelectionRequest/SelectionNotify and INCR for large data;
  use native asynchronous data offers on Wayland/macOS/Windows adapters.
  Never return a success or an empty image before required bytes are ready.
  **Status: NOT RUN.**
- [ ] **OS clipboard ownership without competition**: one native adapter per
  OS; on X11 use the `CLIPBOARD` selection (not `PRIMARY`), XFixes owner-change
  events, timestamps, TARGETS and selection-clear rules. Claim ownership on
  a genuine new remote offer, ignore own changes, suppress echo loops with
  source/generation, and yield when a local app or clipboard manager (for
  example Qlipper) becomes owner. Do not repeatedly reclaim selection from
  a timer or mistake a manager's reoffer for fresh remote content. Test
  ownership handoff, INCR, local copies and races with disconnect/reconnect.
  **Status: NOT RUN.**
- [ ] **Native clipboard file streaming, never whole-file prefetch**:
  negotiate `CB_STREAM_FILECLIP_ENABLED`, `FileGroupDescriptorW` and
  FileContents size/range requests; use `streamId` per file-content request,
  check 64-bit sizes, offsets, bounds and filenames, and support
  `CB_LOCK_CLIPDATA`/`CB_UNLOCK_CLIPDATA` when negotiated. Retain bounded
  metadata and chunk buffers, not entire file bodies; cancel and release
  locks cleanly. CLIPRDR copies files; RDPDR is optional drive redirection.
  For Linux file managers, independently validate a usable destination
  integration (URI/file-descriptor/portal or another native adapter) since
  RDP file streaming alone does not make remote files locally openable.
  Do not require FUSE or `~/thinclient_drives` by default.
  **Status: NOT RUN.**
- [ ] **Real Microsoft-client clipboard acceptance**: macOS screenshot
  taken while Windows App is unfocused, delayed Format List after refocus,
  then remote paste on Linux/X11 into Firefox. Inspect the *synchronous*
  paste event: `clipboardData.items[].getAsFile()` must be non-null with
  MIME `image/png` and the correct screenshot bytes. Exercise immediate
  paste before prefetch completes, repeated paste, local text/image copy
  in both directions, Qlipper competition, PNG/DIB fallback, large INCR
  payloads, file-copy interoperability and clipboard changes mid-transfer.
  An X11 PNG read alone is NOT proof of Firefox file-item acceptance.
  Record client version and capabilities; live host experiments require
  separate authorization. **Status: NOT RUN.**
- [ ] Integrate isolated Linux/X11/Wayland, Windows and macOS desktop,
  clipboard and input adapters; test real Microsoft/FreeRDP clients.
- [ ] Measure native server CPU/RAM, bandwidth, graphics and clipboard
  p50/p95/p99; only then claim performance improvements.
- [ ] **H.264-only interactive desktop baseline first.** Under the existing
  [benchmark standards](benchmark.md), exercise terminal typing/scrolling,
  code editing with syntax highlighting, text-heavy browser scrolling,
  file-manager navigation, menus/dialogs, and mixed text/images/video.
  These are **text-dominant graphical desktop workloads**, not a terminal-only
  protocol or an assumption that pixels have a known content type. Record
  p50/p95/p99 input-to-visible-update latency where measurable; distinguish
  RDPGFX frame ACK from actual presentation. Also record capture/encode/queue
  timings, CPU on older scalar/dual-core hardware, client decode cost,
  network bytes, RSS/allocations, text fidelity and frame drops at fixed
  resolution, load and network conditions. **Tune x264, not competing H.264
  libraries:** start with `superfast` and `zerolatency`, no B-frames/lookahead,
  persistent NV12 input and bounded in-flight work. Compare x264's
  `ultrafast`/`superfast`/`veryfast`, single-frame-thread versus low-latency
  slice threading, and `X264_MBINFO_CONSTANT` unchanged-16x16-macroblock hints
  enabled/disabled. Only set hints verified against the encoder's reference
  history; test frame skips, refresh, resize and reconnect. Compare matched
  visual quality on LAN and bandwidth-limited WAN, prioritizing end-to-end
  latency over encode-only throughput. **Exclude OpenH264 benchmarking and
  generic alternative-encoder evaluations** from this roadmap.
  **Status: NOT RUN.**
- [ ] **Only after H.264 usability is verified, evaluate ClearCodec** as an
  optional optimization, not a prerequisite. Research and test existing
  [IronRDP ClearCodecEncoder](https://docs.rs/ironrdp-graphics/0.9.0/ironrdp_graphics/clearcodec/struct.ClearCodecEncoder.html)
  (Rust, MIT OR Apache-2.0; implemented residual/RLE and small glyph cache,
  but **not** full bands/V-Bar encoding), and the
  [FreeRDP ClearCodec code](https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/clear.c)
  (decoder/reference; `clear_compress()` is unimplemented as of this review).
  First benchmark the candidate offline against the **same dirty rectangles**
  and H.264 settings; assess missing encoder features, output validity,
  client interoperability and licensing before choosing a reusable reference
  or writing a native C++23 encoder. Avoid a Rust runtime dependency in the
  production protocol library. A residual-only prototype does **not** measure
  the full ClearCodec V-Bar cache benefit. **Status: RESEARCH ONLY;
  encode/decode benchmarks and real-client tests NOT RUN.**
- [ ] **ClearCodec go/no-go after measured comparison.** If an interoperable
  implementation provides repeatable improvements in text-dominant GUI
  p95/p99 latency, total CPU/bandwidth or exact text fidelity **without
  unacceptable regressions** in mixed content, memory, security or frame
  correctness, consider an opt-in ClearCodec path and mixed-codec RDPGFX
  synchronization with H.264. Otherwise retain H.264-only graphics and do
  not add a codec for speculative benefit. Preserve the first-party C++23
  architecture and collect reproducible real-Microsoft-client evidence.
  **Status: NOT RUN; decision deferred.**

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
