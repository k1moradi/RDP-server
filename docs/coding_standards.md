# Coding standards — native C++23 RDP server

**Mandatory on every agent prompt:** [AGENTS.md](../AGENTS.md),
[VISION.md](VISION.md), the [living TODO](ROADMAP.md), and the
other three domain standards. Record new verified coding and protocol
lessons in this file; do not create a parallel coding-policy document.

## Standards-first protocol design

Microsoft's published RDP protocol definitions are the primary behavior
authority. For each wire change identify the specification, negotiation
capability, message ordering, bounds and negative test. Reject unsupported
or ambiguous inputs rather than inventing private protocol behavior or
copying xrdp-specific workarounds. A documented, version-identified client
exception requires failing evidence and a targeted regression.

Maintain explicit bounded transport, authentication, session, virtual
channel, graphics, input and clipboard state transitions. Keep wire/core
source independent of OS libraries and place capture/input/clipboard
integration behind distinct adapters. One authoritative owner per
connection/session and clipboard generation; no competing state machine.

## C++23 implementation and memory layout

- RAII for sockets, crypto, memory, files, handles, locks and callbacks.
  Prefer `std::unique_ptr` and deterministic lifetime; use shared
  ownership only when justified, no raw owning `new`/`delete`.
- Prefer contiguous `std::vector`, `std::array`, `std::span` over
  pointer-chasing node containers. Borrowed views may never outlive
  their buffer. Use allocation-free `std::string_view` format routing.
  `std::make_unique_for_overwrite<std::byte[]>` is suitable only when
  every allocated byte is written before use.
- Specify lengths, allocation limits, offsets, byte order, index and
  stride invariants. Check all overflow/conversions before arithmetic
  or buffer access, including untrusted PDU and image metadata.
- Cache fixed strides and lengths outside hot loops. Use `reserve`,
  moves, `emplace`, SIMD and `std::fma`/`std::fmaf` only when the
  result is correct and measurements justify it. Scalar paths remain
  the interoperability and numerical reference.
- Use human-readable names, narrow scopes, `constexpr`, `[[nodiscard]]`
  and documented invariants. Do not erase existing comments, rename
  public APIs or perform broad refactors without an explicit need.

## Concurrency, failure paths and security

Document session event-loop affinity, lock order and ownership.
Bound pending work, queue sizes, response payloads and timers.
Cancel and quarantine late responses on timeout, generation replacement,
disconnect or owner loss; stale data cannot be published in a new
session. Reject malformed DER/Unicode/frames; do not confuse successful
TLS/CredSSP parsing with OS session authorization.
Use fail-only logging, never credentials or user clipboard bytes.

GCC/Clang `-Wall -Wextra -Wpedantic -Werror`, MSVC `/W4`,
standard C++23, portable library first; no xrdp/VNC runtime.
Extend native tests for positive and negative cases and use sanitizers
where supported. See [testing_standards.md](testing_standards.md).

## Preserved lessons

CLIPRDR format response does not provide a universal wire request ID:
retain single-flight ambiguous requests and generation-aware bookkeeping.
X11 PNG delivery to a generic consumer does not prove Firefox obtained
a non-null synchronous image `File`. CLIPRDR file streaming is distinct
from RDPDR drive browsing; neither protocol intrinsically requires FUSE.
Record new facts here and update the same existing TODO.

## Native clipboard implementation rules (2026-10-14; design, NOT RUN)

Use [MS-RDPECLIP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeclip/8bb14d95-fcfa-45e9-b822-f97b129ff208)
(CLIPRDR) for text, image format data and copied-file streams.
[MS-RDPEFS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/)
(RDPDR) is separate optional redirected-file-system access, not the
prerequisite for clipboard file paste. Preserve one first-party portable
clipboard session owner and OS-specific adapters; extend the existing
`RemoteTransfer` generation/format-request coordinator rather than duplicating
it. No xrdp/FreeRDP runtime, FUSE mount or file-cache daemon is required.

- **Announcement is not data:** a client's Format List is only an offer.
  Client focus or OS clipboard privacy rules may delay an offer (observed
  with Windows App on macOS); the server must not assume an unadvertised copy
  exists or bypass client permission. For each advertised generation retain
  separate offered/requested/receiving/ready/failed state. Registered formats
  such as `PNG` and `FileGroupDescriptorW` map by *name*, not globally
  stable numeric IDs. The ordinary Format Data Response has no request ID:
  serialize requests; drain old-generation replies before advancing; if a
  timeout makes matching ambiguous, fail closed/reset the channel instead of
  assigning stale data to a new generation.
- **Prefetch policy:** after a legitimate offer, boundedly prefetch
  `CF_UNICODETEXT` and preferably PNG for images; if needed, request
  `CF_DIBV5` or `CF_DIB` and convert using checked dimensions. Prioritize
  an actual paste over speculative requests. Store only validated,
  compressed image content (and limited text) per current generation;
  lazily decode/convert to consumer formats and cap decoded pixel memory,
  CPU time and queued work. Never serve partial/stale payloads. Prefetch
  may move clipboard contents before paste: expose an explicit session
  clipboard-sharing policy and avoid secret-bearing logs.
- **Waiting must make progress:** X11 `SelectionRequest`/INCR, CLIPRDR
  channel I/O and worker completion are asynchronous. Retain each waiting
  paste request with a deadline; advance unrelated desktop/session events
  while fetching/converting, then complete it or report failure.
  `std::this_thread::sleep_for` or blocking condition-variable waits on the
  event thread can deadlock the very transfer being awaited. A dedicated
  worker may wait on a condition variable with cancellation and timeout.
- **Selection ownership:** on X11 monitor `CLIPBOARD` with XFixes,
  selection timestamps and owner identity; do not seize `PRIMARY`.
  Publish an actual remote generation once and relinquish to local
  applications or clipboard managers without timer-driven reclaiming.
  Ignore self-origin changes, suppress loops using origin/generation
  and handle owner loss while an INCR transfer is in flight. Wayland,
  macOS and Windows use their own native data-offer/clipboard APIs.
- **File transfers:** CLIPRDR `FileGroupDescriptorW` metadata and
  `CB_FILECONTENTS_REQUEST/RESPONSE` ranges use a distinct `streamId`;
  validate indices, 64-bit sizes/offsets, path traversal, cancellation
  and chunk limits. Negotiate file locks where supported; release on
  completion/disconnect. Cache metadata and bounded buffers only, not
  whole files. A desktop file manager may still require a usable local
  file URI, file descriptor or portal adapter; do not claim wire-level
  streaming alone solves that OS integration.
- **Browser criterion:** a successful X11 `image/png` selection read
  is not proof of a Firefox `DataTransferItem` file. Require actual
  synchronous `paste` event inspection with non-null
  `getAsFile()`, MIME `image/png` and matching screenshot contents.

## TCP intake implementation decision (2026-10-14)

RFC 1006 treats TCP as a byte stream, **not** as a sequence of complete
TPKTs. `PreauthConnectionStream` therefore buffers no more than the
initial 260-byte X.224 CR, validates the four-byte length before copying
the rest, returns the exact consumed prefix and leaves any coalesced
TLS data to the caller. Invalid framing terminates the diagnostic;
unsupported proposals use the existing protocol-defined negotiation
failure before closing. The caller must send the whole X.224 Confirm
**before** handing the stream to TLS; no app-data authorization occurs.
Avoid a second transport/session state owner or speculative network
listener until a real TLS and session admission boundary exists.

## X.224 send-before-TLS invariant (2026-10-14)

An X.224 Connection Confirm must be fully transmitted **before** the
external security provider begins TLS (MS-RDPBCGR 3.3.5.3.2).
The single `PreauthConnectionStream` state owner now requires exactly
one `onConnectionReplySent(true)` acknowledgment before allowing
`onTlsHandshake`. Transport adapters must report success only after
the full response was written; partial send, false completion and
duplicate acknowledgment fail closed. A caller-provided bool is still
only an internal test signal and does **not** establish real TLS,
CredSSP or session authorization.

## TLS-record independent MCS framing (2026-10-14)

The decrypted stream from a TLS provider has **no RDP TPKT message
boundaries**. Feed it to the existing single-owner preauth stream
rather than assuming one TLS read equals one Basic Settings Exchange
PDU. MS-RDPBCGR 2.2.1.3 encodes the initial MCS/GCC request inside
a 4-byte TPKT plus a 3-byte X.224 Data TPDU. Validate TPKT
version/reserved/length (bounded to 8,192 bytes), then X.224 before
buffering BER; consume only the first envelope. Reuse the preauth
storage and zero its occupied bytes after close. No parser evidence
alone implies authenticated session admission.

## OpenSSL server TLS evidence boundary (2026-10-14)

Per MS-RDPBCGR 5.4 Enhanced RDP Security and 3.3.5.3.2,
the X.224 Confirm must be **fully sent** before entering the
external TLS provider. An arbitrary `bool completed` from a future
socket adapter is not sufficient evidence that a TLS server handshake
happened. The single `PreauthConnectionStream` owner now checks a
borrowed OpenSSL `SSL*` for **server role**, completed handshake,
TLS version 1.2+, negotiated cipher, and selected certificate before
advancing to the diagnostic MCS parser. Only a *borrowed* `SSL*`
is accepted; lifetime, encrypted network I/O, certificate provisioning
and cancellation remain caller-owned. A TLS handshake alone does not
authenticate OS accounts or approve an RDP desktop session.

## OpenSSL / Windows C++ header hygiene (2026-10-14)

Including OpenSSL's full `ssl.h` in a public portable C++ header
can transitively introduce platform macros such as `min` on MSVC.
Use only `openssl/types.h` in a public header when borrowing
`SSL*`, and include `openssl/ssl.h` privately in implementation
and actual TLS tests. Where a Windows compatibility macro can still
interfere, write `(std::min)(...)` to call the standard function
without macro expansion. The failure was at the compiled native
transport boundary; maintain `/W4` and do not skip Windows CI.

## First decrypted TLS application-record bridge (2026-10-14)

MS-RDPBCGR sections 5.4.2.1 and 3.3.5.3.2 place the MCS Connect
Initial in the established TLS channel. The existing preauth stream
now holds a borrowed pointer **identity** to the previously verified
server-side SSL session, preventing a caller from substituting an
unrelated TLS object on the new read path. Limit `SSL_read_ex` to
the next TPKT boundary; OpenSSL may internally decrypt coalesced TLS
application records, but the parser MUST NOT consume later RDP
PDUs. A retryable WANT_READ/WANT_WRITE requires transport event-loop
progress, not a busy loop. Missing SSL, wrong role/identity, EOF and
malformed framing always fail closed. The caller owns the TLS
provider, BIO/socket lifetime, encrypted network pump and cancellation;
no ownership of SSL or authenticated OS identity is transferred.

**Verified on hosted systems:** the borrowed-SSL read path and bounded
TPKT-preserving algorithm at `a226f15827e9da48ad7a91b7cfa53528c3498802`
passed [Actions run 38557465241](https://github.com/k1moradi/RDP-server/actions/runs/38557465241)
on Ubuntu, macOS and Windows. Keep network I/O cancellation and
user authorization separate from validated TLS record decoding.

## Real nonblocking X.224 send progression (2026-10-14)

MS-RDPBCGR 3.3.5.3.2 requires the server to send the X.224
Connection Confirm before invoking external TLS and to send
RDP Negotiation Failure before closing. The former boolean
`onConnectionReplySent(true)` could be misreported after a
partial socket write, violating that ordering. Use the sole
connection owner's `pendingConnectionReply()` suffix and
`onConnectionReplyBytesWritten(n)` event to account for exactly
the bytes accepted by the OS. Zero-byte progress does not advance;
over-count, replay, invalid state and hard I/O failure close
without TLS admission. The rejected-security path may drain
the error PDU while remaining terminal. No duplicated send
state, separate controller, socket listener or private protocol.

**Verified:** implementation commit `98f6fdc60d513d47a87a78fadf1aa6be387da28b`,
[Actions run 38561127854](https://github.com/k1moradi/RDP-server/actions/runs/38561127854)
passed GCC/Linux, Clang/macOS, MSVC/Windows, documentation-policy,
all Debug/Release CTests, SDK consumer and packaging checks. This
does not yet establish live network service or OS user admission.

## Borrowed platform socket transport boundary (2026-10-14)

Keep OS socket system headers inside the thin
`nonblocking_tcp_adapter.cpp` implementation. The portable interface
reports progress, would-block, EOF and hard failure explicitly;
byte counts larger than the exact span offered are invalid. A
preauth TCP read MUST request only the next needed TPKT header/body
bytes (4 then length-4, at most 260 total) to avoid accidentally
consuming a coalesced TLS ClientHello before the security reply
is fully sent. A send MUST use only the owner's pending reply
suffix and acknowledge exactly bytes written. On Windows the socket
owner initializes Winsock, on BSD/macOS protects against SIGPIPE,
and everywhere configures nonblocking mode, event readiness, lifecycle
and close. The portable static library does not open a listener or
authorize OS access.

**Verified cross-platform:** implementation SHA
`dd3a806f97b13e6db18affd689c6321bfa009813`,
[Actions run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
passed the Debug/Release portable protocol suite, downstream SDK
consumer and packaging gates on Linux/GCC, macOS/Clang and Windows/MSVC,
plus documentation-policy. Native socket syscalls were compiled but
actual connected native socket traffic is not covered by this test;
do not infer live server or user authentication.

## Synthetic certificate ownership on OpenSSL 3 and 4

Do not assume `X509_get_subject_name` yields writable storage:
OpenSSL 4.0.3 returns a const name. The native TLS test fixture
should own a separate mutable name via RAII `X509_NAME_new` and
install it through `X509_set_subject_name` and
`X509_set_issuer_name`, then sign. Do not use `const_cast`,
weaken assertions, silently pin OpenSSL to hide a compiler
error, or confuse test self-signed certificates with
trusted production credential management.

**Post-fix evidence:** `5c4f3ad7273d17948327b7d351ff9840de2b0395`,
[CI run 38564403002](https://github.com/k1moradi/RDP-server/actions/runs/38564403002)
passed Linux, macOS and Windows Debug/Release tests and SDK gates.
The successful macOS runner selected OpenSSL 3.6.4, so OpenSSL
4 compile compatibility after the RAII fixture change remains
unverified until an explicit 4.x compile is recorded.

## Nonblocking TLS readiness and borrowed SSL identity (2026-10-14)

Keep server-side TLS handshake progression on the **same**
`PreauthConnectionStream` that tracks X.224 Confirm output and
will parse the first MCS/GCC frame. `SSL_do_handshake` must be
invoked **once per ready event**, and its `SSL_get_error` checked
immediately on a failed result. WANT_READ and WANT_WRITE are
retryable without inventing a timer or spinning. The first
server SSL pointer is borrowed until success/cancellation,
so another OpenSSL handle cannot take over a partially
started handshake. Full reply-write acknowledgement remains
mandatory before the first TLS operation. Provider cancellation
clears the SSL pointer and buffers; neither cryptographic
transport completion nor a temporary self-signed test
certificate authorizes a real user or OS session.

**Verified cross-platform:** the one-owner nonblocking TLS
handshake API at `fcd05f8e903a459ca85f13807bd35f7091f3fd70`
passed [Actions run 38566584099](https://github.com/k1moradi/RDP-server/actions/runs/38566584099)
on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
with **25** Debug/Release CTests and per-OS package verification.
Keep certificate trust, live sockets and identity authorization
independent of this in-memory protocol handshake evidence.

## Nonblocking OpenSSL BIO over native socket adapter (2026-10-14)

OpenSSL permits custom nonblocking `BIO_METHOD` operations through
`BIO_meth_set_read_ex`, `BIO_meth_set_write_ex` and retry flags.
Map the existing borrowed `TcpNonblockingIo` exactly: positive
counts no greater than the offered span progress; WouldBlock sets
the matching BIO read/write retry bit; FIN, errors, invalid counts
and zero-success never count as progress. Use `SSL_set_bio` once
to transfer the BIO into SSL; it MUST NOT transfer ownership of
the socket or adapter. Verify no previous BIO/handshake exists.
This avoids narrowing Windows SOCKET handles and keeps
platform-native headers out of the protocol core. Avoid
spin-polling inside production TLS callbacks; one handshake
operation is driven per event-loop readiness event. Test-only
port-zero IPv4 loopback connections must be short-lived, bound
to 127.0.0.1 only and must never authorize an OS desktop session.

**Verified native BIO loopback boundary:** the implementation
`7ce64737ccef439af2f0cfd383208181cc0e9513` passed
[CI run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
on GCC/Linux, Clang/macOS and MSVC/Windows, including
Debug/Release 27 registered CTests and SDK consumer/package gates.
Short-lived native TCP loopback traffic and encrypted OpenSSL
records were exercised; user authorization and real external
RDP client interoperability are NOT RUN.

## MS-RDPBCGR/T.125 MCS domain merge (2026-10-14)

For Connect-Initial processing, follow Microsoft's published
[MergeDomainParameters algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7617f746-95c9-4a6e-808d-e2f642471e86)
rather than assuming the target set can be copied to the server
response. Apply the precise minimums (four channels, three users,
one priority and one domain hierarchy level), bounds on
maxMCSPDUsize, and effective protocolVersion 2. The minimum and
maximum protocolVersion BER fields are individually legal without
being 2; reject when their range cannot negotiate 2. Reject any
merge failure **before** channel/domain allocation or a response;
return an empty value so callers cannot reuse partial negotiation
state. A successful merge does not authenticate credentials or
authorize an OS session. Never allocate according to client
advertised 32-bit quantities without a later independent budget
and real-user admission gate.

## T.125 BER / T.124 PER Connect-Response encoding (2026-10-14)

Use the canonical wire formats from
[MS-RDPBCGR 2.2.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c)
and its annotated 4.1.4 example: APPLICATION 102 `7F 66`,
BER ENUMERATED success `0A 01 00`, zero calledConnectId,
merged eight-field DomainParameters encoded as minimal
nonnegative BER INTEGERs (include sign-protecting zero octet),
and an OCTET STRING holding GCC ConferenceCreateResponse.
Use bounded nonfragmented PER length, legal GCC nodeID
1001..65536 offset and H.221 key `McDn`.
Only Enhanced TLS is currently supported; `SC_SECURITY`
encryption method/level must both be zero with NO legacy
server random or RC4 proprietary server certificate.
`SC_NET` channel IDs must match client-requested count,
be nonduplicated, and obey the merged channel limit; odd
counts need two padding bytes. The serializer must not
own channels, admit users, send to a live peer, or reuse
a partial packet after rejection.

## T.125 channel-connection PER syntax-only boundary (2026-10-14)

For MS-RDPBCGR sections
[2.2.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/04c60697-0d9a-4afd-a0cd-2cc133151a9c),
[2.2.1.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f5d6a541-9b36-4100-b78f-18710f39f247)
and
[2.2.1.8](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/64564639-3b2d-4d2c-ae77-1105b4cc011b),
reuse the existing `parseDataTpdu` validator for exactly one
complete TPKT. Recognize aligned PER DomainMCSPDU choice octets
0x04, 0x28 and 0x38; reject other directions/types and extra
data. For Erect, require both bounded, present PER INTEGER
values with canonical lengths. For Join, decode UserId as the
big-endian wire offset + 1001 with overflow protection, but
never infer that the user or requested channel has been
allocated or joined. Even a syntactically valid out-of-domain
channelId must be checked by the future authenticated domain
owner. Do not fork the MCS parser or create a competing
session or channel controller.

**Verified parser boundary:** the strict T.125 Erect, Attach and
ChannelJoin decoding increment at
`6effdb76229e2514511ebe5dd8cb404841403b1b` passed
[Actions run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653)
on GCC/Linux, Clang/macOS and MSVC/Windows, including full
Debug/Release **37 CTests** and SDK gates. An early incorrect
PER test-vector length was corrected without changing the
strict decoder; do not interpret this as authenticated domain
or channel admission.

## Offline MCS Attach/Channel success encoding (2026-10-14)

Follow T.125 BASIC aligned PER semantics and the exact server
wire samples of [MS-RDPBCGR 4.1.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3b3d850b-99b1-4a9a-852b-1eb2da5024e5)
and [4.1.8.2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7443e65e-3482-4cec-823a-741eb1fe27b4):
`2e 00 [UserId offset:2]` and
`3e 00 [UserId offset:2] [requested:2] [channelId:2]`,
framed with exact TPKT and X.224 bytes. Never choose, reserve,
attach, or join identifiers in a serialization function.
Fail closed on assigned UserId outside 1001..65536, a
mismatched client initiator, wrong request variant, unallocated
or multiply listed requested channel, or empty/oversized
allocation list. The future authenticated domain controller
must perform an independently audited admission before using
any positive response on a socket. Synthetic tests and
caller-provided lists are not identity evidence.

**Cross-platform evidence:** offline Attach User Confirm and
Channel Join Confirm encoders at
`4eb3bff4f9fc15cb72da1b8e994ec89e7e9a96db`
passed [CI 38590263498](https://github.com/k1moradi/RDP-server/actions/runs/38590263498)
on GCC/Linux, Clang/macOS and MSVC/Windows, with
Debug/Release 39 named CTests, documentation-policy and
installed SDK consumer/package gates. This does not prove
any identity, host admission, channel allocation or
actual RDP client acceptance.

## MCS disconnect PER encoding and lifecycle ownership (2026-10-14)

Under [MS-RDPBCGR 2.2.2.3/4.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/19a238a5-0455-46f0-a96b-31320d9a70a1)
the complete Disconnect Provider Ultimatum is nine
TPKT/X.224/aligned-PER octets, and its two-bit reason
straddles the final octets. The pure server encoder may
emit only reasons 1 (provider initiated) or 3 (user requested);
all invalid enum values return no packet. The receiving
server must ignore all four two-bit reason values, while
rejecting invalid TPKT lengths, choice/extension bits,
and nonzero PER padding. No heap, second owner, new protocol
transport, or session policy in this primitive. Only
the one future authenticated TLS owner may transmit the
entire encrypted PDU and close after write completion.
Offline wire correctness is not an RDP disconnect acceptance.

## Bounded zero-copy MCS Send Data Request (2026-10-14)

Keep T.125 client SendDataRequest in the existing
`parseMcsChannelRequest`, reusing the canonical checked TPKT/X.224
envelope validator. Per MS-RDPBCGR 4.1.16, choice 25 (0x64)
has a PER initiator offset +1001, channelId, two-bit priority
and segmentation, four zero padding bits, and userData carried
as an aligned-PER OCTET STRING.

Check bounds for every field before reading. Accept both short
7-bit and long 14-bit PER length determinants (including long
form for a short payload, for real-client interoperability);
reject fragment determinants, inconsistent lengths, TPKT
surplus, invalid padding and initiator overflow. A single
PER userData field is at most 16383 bytes. Return a borrowed
`std::span<const std::uint8_t>` without copying, with lifetime
tied to the caller's unchanged complete packet. The owning TLS
read buffer must not be reused while that view is consumed.
No worker-thread handoff or cached span is safe without a
separate, explicit owned snapshot and bounded lifecycle.

These syntax fields do not indicate authentication, channel join,
complete fragmented messages or eligibility for clipboard,
graphics or OS input. Only the future single authenticated
session owner can verify transport, identity and channel rights
before dispatch; the parser never performs admission.

## Offline server MCS Send Data Indication (2026-10-15)

MS-RDPBCGR 1.3.1.1 and 2.2.6.1 require server-to-client
post-channel traffic to use T.125 `SendDataIndication`
(DomainMCSPDU choice 26, 0x68), never the client's
`SendDataRequest` choice 25 (0x64). Reuse the original
`mcs_channel_connection` module for this encoder; do
not create a parallel session controller. Emit one full
TPKT/X.224/aligned-PER frame into caller-provided
`std::span<std::uint8_t>`. Require valid UserId
1001..65536, nonzero caller-supplied channel, two-bit
priority and segmentation, and unfragmented PER userData
at most 16383 bytes. Use one short determinant below 128
and a two-octet determinant from 128; validate output
capacity BEFORE writing any byte. The caller can pass
input overlapping output: use a single `std::memmove`
for the opaque payload BEFORE writing its header, so no
source bytes are destroyed. Do not allocate or touch any
output suffix. Failure must leave the entire destination
unchanged. Only authenticated owner-supplied authorization,
TLS provenance and joined MCS state may allow actual
SSL transmission; this encoder never grants permission.

## Server Demand Active writer: validate before mutation (2026-10-15)

MS-RDPBCGR 2.2.1.13.1.1 and 3.3.5.3.13.1 require
the outbound server Demand Active Share Control PDU
with source pduSource=1002, type/version 0x0011,
LE16 totalLength/sourceDescriptorLength/combinedCaps,
caller-supplied shareID and sessionId, a counted
sequence of TS_CAPS_SET, and no Share Data header.
Reuse the original `mcs_channel_connection` module.
Use the SAME first-party helper to validate all
capabilitySetType/lengthCapability envelopes on
both inbound and outbound paths: each envelope is
at least four bytes; count and declared data sizes
must consume exactly the concatenated input.

Validate descriptor and combined lengths against
LE16 maxima, full packet <=65535, reject
`totalLength=0x8000` because that value means a
must-ignore FlowPDU, check output capacity and
input/output overlap BEFORE any destination mutation.
The two independent opaque input spans must not
overlap the destination region being written:
reject rather than risk corrupting yet-unread bytes.
Do not allocate internally; preserve unused suffix
and leave output completely unchanged on rejection.
Empty/unknown capabilities are accepted as framing
only, NEVER as a negotiated or supported server
graphics/clipboard/input feature. This offline
encoder does not perform TLS or MCS writes and
cannot bypass the genuine security/OS admission gate.

## Correlate activation transcript without granting authority (2026-10-15)

For the T.128 Demand Active -> Confirm Active exchange,
reuse the existing `parseRdpActivePdu` twice in the same
first-party transport translation unit. Confirm must be
type 3 with originatorID=0x03EA and sender pduSource
equal to the separately assigned 16-bit client user ID.
Demand must be type 1 with normative server
pduSource=0x03EA; the 32-bit share IDs MUST match.
Refuse user IDs below 1001 and beyond 65535 before
any narrowing conversion; a T.125 65536 initiator
cannot be represented by 16-bit Share Control source.
The complete input boundaries, opaque capability counts
and lengths remain the parser's responsibility. Do not
introduce a second parser, activation controller, cache,
heap allocation or TLS send. Return only
`ConsistentSyntaxOnly` or `Rejected`, never a
privileged, authenticated or session-admitted result.

A successful syntax correlation MUST NOT authorize
the OS account, prove client originator channel
membership, compare negotiated capability contents,
satisfy licensing, advance the live state machine,
or grant desktop graphics/input. The assigned-client-
user-ID argument is caller-supplied syntax, not
independently verified MCS identity. Only one later
genuinely Kerberos/TLS-bound, independently OS-approved
session owner may enforce those separate decisions.

## Checked Demand/Confirm Active capability envelopes (2026-10-15)

MS-RDPBCGR 2.2.1.13.1.1 (Demand Active) and 2.2.1.13.2.1
(Confirm Active) use distinct fixed prefixes after the shared
six-byte TS_SHARECONTROLHEADER. Demand has LE32 shareID,
LE16 source length, LE16 combined-capabilities length,
source bytes, LE16 count + ignored LE16 pad, N capability
sets and exact terminal LE32 sessionId. Confirm adds an LE16
originatorID=0x03EA after shareID but has no sessionId.
The combined length INCLUDES count + pad, NOT sourceDescriptor.
Every TS_CAPS_SET is at least 4 bytes, with LE16 type and
LE16 lengthCapability INCLUDING those four bytes. Validate
fixed prefix sizes, all source/combined/subcap boundaries
using remaining-span subtraction, reject cap counts that
cannot fit even four-byte headers, demand exact consumption,
and never accept truncated or surplus bytes. Avoid heap
allocation and return only caller-lifetime borrowed spans.

Unknown TS_CAPS_SET types MAY be preserved as opaque
envelopes; the published Microsoft Demand Active packet
contains a four-byte FONT set that is malformed against
its ideal typed schema but valid as a four-byte envelope.
Do not pretend envelope recognition negotiates font,
bitmap, AVC420 or any capability. Ignore pad2Octets.
A valid Confirm originatorID=1002, sourceID or shareID
is untrusted syntax, not MCS permission, authenticated
identity, share admission or license acceptance. Only
the single future owner may validate direction,
session-specific shareID, the *contents* and required
sets, active TLS-bound GSS, independent OS policy and
ordering before any real activation or input.

## Fail-closed server finalization serialization (2026-10-15)

MS-RDPBCGR 2.2.1.14.1, 2.2.1.15.1, 2.2.1.19,
2.2.1.20 and 2.2.1.21 govern server-side
Synchronize, Control Cooperate and Control Granted.
Implement these fixed-size uncompressed Share Control
and Share Data packets in the SAME existing C++23
`mcs_channel_connection` owner. Reuse one private,
allocation-free writer for the common 18-byte Share
Control/Data header with pduSource=1002, protocol
version/type=0x0017, caller shareID, explicit
uncompressedLength, canonical zero pad and compression
flags. Synchronize is 22 bytes, stream 0, type2 0x1f,
messageType=1 and an uninterpreted LE16 targetUser.
Microsoft's uninitialized Server Synchronize targetUser
example forbids assuming that a valid value proves
assigned membership. Control is 26 bytes, stream 2,
type2 0x14, valid server actions ONLY Cooperate (4)
and Granted Control (2). Cooperate requires zero
assignedClientUserId and writes grant/control IDs 0/0;
Granted requires 1001..65535, writes that user ID
and server channel 1002. Reject Request Control, Detach,
out-of-range user IDs, unknown actions, and short output
capacities BEFORE touching any output octet. Preserve
caller output suffix and perform no heap allocation.

Never interpret a valid emitted Granted Control packet
as an OS permission, MCS join result, successful GSS/TLS
authentication, licensing result or share activation.
Real message ordering, TLS output and resource access
belong only to a future separately authorized session
owner. These offline writers do not form an independent
state machine or encryption layer.

## Pure finalization PDU syntax is NOT an activation controller (2026-10-15)

MS-RDPBCGR 2.2.1.14.1 and 2.2.1.15.1 define small,
fixed-size T.128 finalization messages. Extend ONLY the
first-party `mcs_channel_connection` Share Data parser,
not a new state manager. `TS_SYNCHRONIZE_PDU` requires
exactly four body octets, type2 SYNCHRONIZE 0x1f and
little-endian messageType 1; its targetUser LE16 is
untrusted channel metadata. `TS_CONTROL_PDU` requires
exactly eight body octets, type2 CONTROL 0x14, and
LE16 action 1=Request, 2=Granted, 3=Detach or
4=Cooperate, followed by LE16 grantId and LE32
controlId. Reject truncated, coalesced, malformed,
wrong-type, unsupported compressed and invalid
action/message-type packets before returning any
success-shaped structure. Reuse existing nested
Share Control/Share Data strict framing, compression
denial and stream compatibility; no temporary
buffer, heap allocation, or parallel dispatcher.

This layer MUST NOT treat a syntactically valid
GrantedControl action or a targetUser/grantId/controlId
as proof of joined MCS ownership, actual sender
direction, negotiated active share or OS control.
Microsoft's Client Cooperate/Request Control requires
zero grantId/controlId; Server Granted Control uses
assigned UserId and the server channel, but those
directional/session-specific requirements must be
verified by the one authorized connection owner
AFTER genuine CredSSP TLS binding, OS admission,
security-header handling, licensing and capability
negotiation. Do not synthesize a server Granted
Control reply in a parser, emit TLS or admit input.

## Fail-closed T.128 Share Data Header decoding (2026-10-15)

MS-RDPBCGR 2.2.8.1.1.1.2 describes 12 data-header octets
following the canonical six-byte Share Control Header.
Reuse the existing exact-length Share Control parser, then
require kind=Data and at least 12 remaining header bytes
before reading LE32 shareID, ignored pad1, streamId,
LE16 reported uncompressedLength, type2, compression
flags and LE16 compressedLength. Permit the 24 documented
type2 values, streams 1/2/4 and stream 0 ONLY with
SYNCHRONIZE type2 (0x1f). Unknown values fail closed
with no borrowed body. Propagate FlowPDU ignored status,
rather than converting an ignored packet to a Data PDU.

The published Microsoft Client Font List sample contains
an uninitialized uncompressedLength. Keep that field as
metadata, NOT a length check or allocator. The enclosing
Share Control totalLength is the real validated frame
boundary. Likewise pad1 MUST be ignored (real packets
contain nonzero bytes), and in uncompressed mode the
compressedLength is metadata, never an allocation or
payload boundary. Until authenticated decompression and
history ownership exist, reject EVERY nonzero
compressedType (including compressed, flushed and at-front
flags). Never misroute compressed payload to an uncompressed
Data PDU handler. Return a zero-copy borrowed span only
for valid, explicitly isolated, uncompressed Data PDUs.

Actual MCS, TLS, license, security header, active share,
joined channel and independently authenticated OS identity
are mandatory, separately verified future admission gates;
none is inferred from pure Share Data syntax.

## Strict offline T.128 Share Control Header (2026-10-15)

Follow [MS-RDPBCGR 2.2.8.1.1.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/73d01865-2eae-407f-9b2c-87e31daac471):
the six bytes of `TS_SHARECONTROLHEADER` consist of LE16
totalLength, LE16 pduType (12-bit protocol version and 4-bit
type) and LE16 pduSource. The only five documented type values
are 1, 3, 6, 7, and 10; `TS_PROTOCOL_VERSION` must be 1.
Reject any incomplete, coalesced or size-inconsistent complete
input. Distinguish `totalLength=0x8000` as a *must-ignore*
T.128 FlowPDU, not as a request to allocate 32768 bytes and
not as an application message. Do not hand out a borrowed
body for ignored, malformed or unknown frames. Accept source
ID as uninterpreted; a parsed header never proves a negotiated
share, valid channel or account.

The caller must already identify the Share Control PDU after
MCS, optional Security Header, and any negotiated security/
licensing routing. Never assume unclassified MCS userData is a
Share Control PDU. No nested Share Data, compression, capability,
RDPGFX, virtual channel, clipboard or user input interpretation
belongs in this pure parser. Use one checked, borrowed `std::span`
into the full original input, no buffer copies or allocations;
the owning input must remain alive until all views are consumed.

## Strict bounded CredSSP DER framing ownership (2026-10-14)

MS-CSSP 2.2.1 specifies DER TSRequest messages on TLS;
use the existing parser rather than another DER validator.
The first-party `TsRequestFrameReader` is a *framer*,
not a duplicate session authority. Read exactly tag and
length (DER short, 0x81 or 0x82 canonical lengths), reject
indefinite/fragmented/nonminimal/oversized forms before
buffer allocation, and never consume bytes of a coalesced
following TSRequest. Hold sensitive, opaque token bytes
in at most the existing 16 KiB fixed array; borrow views
only until explicit release and cleanse on every cancel
or discard. A complete frame must not be overwritten by
unexpected new input, even when the next input is itself
syntactically valid. Reject an invalid first tag byte within the
same receive step, *before* returning NeedMore on input exhaustion,
even when it was the only byte received. This is a bounded
fail-fast parser invariant, not an authorization change.
No change to NLA flags or authentication
admission may be justified by framing correctness alone.

**Cross-platform validation:** incremental CredSSP DER framing
at `c7f0463a3e11c8bd9fb6e8dfb404c3f1057d40cd`
passed [CI run 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562)
on Linux/GCC, macOS/Clang and Windows/MSVC,
including Debug/Release 46 CTests and installed SDK/package
gates. This is DER framing acceptance only; it does not
authenticate identity or authorize OS/RDP session access.

## Canonical offline CredSSP server response DER (2026-10-14)

MS-CSSP 2.2.1 requires a server TSRequest to contain only the
relevant response field for its current handshake phase. Encode
`negoTokens` with exactly one nested NegoDataItem or `pubKeyAuth`
as an opaque OCTET STRING; do not combine them, introduce
`authInfo`, or serialize a client nonce for server replies.
Use canonical short/0x81/0x82 definite lengths and a single
bounded output reservation with a verified final size.
Restrict the current helper to project-supported versions 5/6
and 8192-byte opaque provider outputs. DER serialization must
never be treated as GSS wrap, principal verification or
permission to advance TLS, MCS or a console session.

## Optional native Linux GSSAPI provider boundary (2026-10-14)

Keep the portable C++23 static SDK free of mandatory Kerberos
dependencies. The Linux-only, opt-in test target may link
MIT GSSAPI implementation files, but must never be installed
as a functioning RDP server or implicitly load a host keytab.
Only explicit TERMSRV/host@REALM and absolute FILE:/ keytab
configuration is permitted by the existing GSS acceptor.
Pass a complete v5/v6 `TsRequestFrameReader` into
`GssapiSpnegoAcceptor::acceptFramedNegoRequest` synchronously;
parse/borrow once, invoke the existing real GSS-API provider
without copying the inbound token, and erase/close on failure.
Keep OpenSSL TLS binding, delegated credentials and OS desktop
admission as independent, unverified gates; GSS syntax tests,
an absent-keytab failure or green builds never grant rights.

## TLS-bound CredSSP streaming and ownership (2026-10-14)

Reuse the first-party `TsRequestFrameReader` for both synthetic
DER fixtures and decrypted real TLS bytes. When reading TLS,
pin the same established server-role `SSL*` throughout all
frames, reject attempts to alternate SSL identities or inject
raw plaintext, and securely clear buffers at every terminal
failure. Keep a 512-byte stack chunk and read only up to
`bytesNeeded()` to avoid consuming the next coalesced frame.
If `SSL_read_ex` produced bytes without completing the
frame, return `Progress` to permit a follow-on call even
when no new socket readiness event occurs. Only on
`SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE` should
the event loop wait. Call `SSL_get_error` immediately after
the failed OpenSSL operation. Explicitly erase transient
decrypted stack bytes after copying into the sole owned DER
buffer. TLS provenance alone does not authorize NLA/GSS,
independent OS identity, or desktop.

## TLS provenance and version pinning for CredSSP GSSAPI (2026-10-14)

MS-CSSP 2.2.1 and 3.1.5 put all SPNEGO tokens and the
pubKeyAuth proof on the *same* TLS-encrypted CredSSP
exchange. A syntactically valid DER view is not evidence
it arrived over the selected TLS session. Carry a borrowed
completed-frame server SSL identity from the already-owned
framer into the existing Linux GSS acceptor and pin
it together with the supported 5/6 CredSSP version.
Reject a mixed parser/TLS handoff, changed SSL pointer,
changed version or pre-initial provider phase without
trying to use GSS credentials. Clear borrowed identity
on terminal rejection; guard protected-binding unwrap
with matching SSL and version before comparing the
selected TLS certificate's hash. No standalone account
capability, stored plaintext, extra controller or generic
SSPI emulation is created. Keep positive Kerberos,
combined final negotiation/binding, credentials and
independent OS authorization open until tested.

## Final combined CredSSP token + pubKeyAuth gate (2026-10-14)

MS-CSSP 2.2.1 and 3.1.5 specify that the last
client `negoTokens` item and protected `pubKeyAuth`
co-occur in one TSRequest. Keep exact one-token,
v5/v6, 32-byte nonce, no-delegated-credentials/no-error
checks in the existing borrowed-span type rather than
inventing a second ASN.1 parser. Accept this final
request only on the single pinned SSL transcript with
an already continuing Linux MIT GSSAPI context. Process
both phases synchronously before wiping/releasing the
existing frame: GSS accept with required mechanism
security flags, unwrap the encrypted binding with
confidentiality, compare against selected TLS certificate
hash and nonce, wrap server proof. If an extra provider
output token remains and the defined server binding
reply cannot carry it, fail closed rather than silently
discard it. The prior binding-only helper remains
independently gated and MUST NOT treat a token-containing
final message as a binding-only request. Do not claim
end-to-end authenticated session admission from
negative-only GSS tests; controlled positive Kerberos
and OS policy verification remain mandatory.

## Secure nonblocking CredSSP server reply transport (2026-10-14)

For MS-CSSP 2.2.1/3.1.5, keep server-side
`negoTokens` and encrypted `pubKeyAuth` replies
within the existing canonical encoder, never accept
arbitrary preframed DER or raw GSS bytes for direct
TLS transport. Queue exactly one bounded 16 KiB
reply with a pinned server `SSL*` after TLS 1.2+
handshake completion and selected certificate/cipher.
`SSL_write_ex` can partially write or return
WANT_READ/WANT_WRITE; a stable owned vector must
remain unchanged, with the *same pointer and remaining
length* across all retry calls when OpenSSL reports
WANT and offsets advanced **only** for successful
writes. Never reinterpret WANT as EOF, spin on
readiness, overwrite a pending reply, send twice
after Complete or permit SSL pointer substitution.
Cleanse the payload on release/cancel/error, preserve
SSL provenance only across explicit successful
release, and leave policy to the one future trusted
CredSSP/session owner. Green TLS wire tests alone
are not positive GSS or OS authorization evidence.

## Linux MIT GSSAPI -> TLS writer handoff (2026-10-14)

When forwarding real provider tokens per MS-CSSP
3.1.5, source the TLS pointer only from the
currently complete actual server-side
`TsRequestFrameReader` frame. Neither
caller-provided DER nor an unrelated `SSL*`
can impersonate that identity. During
SPNEGO, queue `negoTokens` ONLY for an
actual `GSS_S_CONTINUE_NEEDED` result with
nonempty opaque output; if context completes
on a negotiation-only frame without the
mandatory client final binding, reject rather
than accepting a wrong stage. Require any
previous TLS server response to be completely
sent AND explicitly released before consuming
a subsequent GSS client token. The final client
request must contain combined `negoTokens`
and confidential client `pubKeyAuth` in
the single same-TLS frame. Only a real GSS
context plus successful version-pinned TLS
binding may queue the confidentially wrapped
server proof. The producer's temporary
GSS token vector must be cleansed once its
bytes are snapshotted by the writer; clear
reader/writer/context on every failure.
The helper merely queues a response for a
future TLS readiness loop; it does NOT
create an authenticated OS session, perform
credential delegation, alter X.224 selection
or emit MCS domain/channel responses.

## Selected server certificate continuity for CredSSP (2026-10-14)

Per MS-CSSP 2.2.1/3.1.5, the v5/v6 client/server
proof uses the SubjectPublicKey from the server's
selected TLS certificate, with a direction-specific
NUL-terminated binding label and the client's
32-byte nonce. Do NOT hash the peer certificate,
a mutable SSL_CTX default before handshake, the
full SubjectPublicKeyInfo or raw TLS bytes.
Validate finished TLS >=1.2, server role, active
cipher and selected certificate in ONE existing
certificate module. SHA-256 fingerprint the selected
DER certificate on the FIRST authentic TLS read,
pin it alongside the existing `SSL*`, compare it
in constant time before every later read and
completed GSS handoff, and fail closed on same-SSL
certificate substitution/renegotiation.
Do NOT reset the pin merely because a successfully
parsed frame is released; wipe it on the reader's
terminal close. No GSS token, binding hash or
certificate fingerprint is a user-authorization
capability. Test with actual OpenSSL selected
certificates, never a fabricated OS identity.

## Frame-proven GSS pubKeyAuth only (2026-10-14)

The optional Linux MIT GSS binding implementation
must never accept a caller-provided
`std::span<DER>` paired with a seemingly valid
`SSL*` as proof of TLS record provenance.
Keep the legacy public method only as
deny-only for callers that might still
compile against it. The one trusted
`TsRequestFrameReader` must supply
`completedFrameServerTls()` and a
borrowed, bounded DER span until the
synchronous real GSS unwrap, selected
cert/nonce check and server GSS wrap end.
For the binding-only form require NO
negoTokens, EXACTLY encrypted pubKeyAuth
and a 32-byte nonce, no authInfo/errorCode,
matched negotiated 5/6 version, verified
GSS context and unchanged active TLS
certificate. For the combined final
message preserve its independent strict
shape and GSS completion requirement.
Reuse a single checked reply queue
implementation for both variants;
reject non-idle writers and erase
transient GSS-protected provider output
after snapshotting bytes into the
existing canonical TLS writer. Never
promote these components to OS or
MCS authorization authority.

## Outgoing CredSSP TLS selected-certificate continuity (2026-10-14)

The nonblocking server `TsRequestTlsReplyWriter`
must validate more than `SSL*` pointer
equality: a selected server certificate
may be reconfigured on the same SSL
object between responses or between
`SSL_write_ex` retries. Pin SHA-256
of the actual selected DER X.509
certificate on the first queued
canonical TSRequest v5/v6 reply.
Reuse the existing strict finished
TLS >=1.2 server-role/cipher/certificate
check and compare the pinned digest
with `CRYPTO_memcmp` at each step,
including Complete and release and
the next queue after release.
Keep the original digest across
successful reply release and cleanse
it on terminal close; cleanse the
transient fingerprint on ALL return
paths. Preserve the stable owned
DER pointer and size across WANT.
Reject a mismatch BEFORE any
additional `SSL_write_ex`, wiping
the pending reply and terminating
the writer. A previous successful
SSL write cannot be recalled.
Do not confuse transport continuity
with GSS provider authentication,
OS authorization or session admission.

## Cross-reader GSS transcript certificate identity (2026-10-14)

Even correct individual `TsRequestFrameReader`
certificate pinning is insufficient if application
code constructs a new reader per CredSSP round.
The existing Linux GSS acceptor MUST pin its own
selected server DER X.509 SHA-256 identity at
the first TLS-derived token, compare it
constant-time at all later same-SSL GSS/
pubKeyAuth/frame/writer handoffs, and cleanse
the pin during terminal `reject()`.
Neither the public raw-DER legacy deny-only
API nor a fresh reader may bypass this policy.
Do not elevate a verified Kerberos SPNEGO
context to authorization: the OS adapter
must still independently approve a session.

The opt-in real provider probe must use ONLY an
explicit `TERMSRV/host@REALM` service principal,
explicit `FILE:/` keytab and separately specified
`FILE:/` initiator credential cache. It must NOT
load a host default keytab/cache, fabricate
provider success, spin up an implicit KDC,
start an RDP listener or accept an OS account.
Use existing native GSS and OpenSSL TLS fixture
and one current connection owner; never log
or commit credentials.

## GSS provider-only CredSSP v6 negative reply dispatch (2026-10-15)

The existing first-party Linux MIT GSSAPI acceptor MAY queue
a terminal version-6 `TSRequest.errorCode` under Microsoft
MS-CSSP 2.2.1/3.1.5 ONLY after the configured, explicit-keytab
`gss_accept_sec_context` actually rejects a client token or
rejects its completed security/mechanism flags. Internal
`SpnegoStep.providerRejected` is the evidence carrier, not an
injected caller verdict or identity credential. A missing keytab,
bad TLS provenance, wrong/premature version, malformed DER,
invalid pre-GSS initial tag/OID, failed local memory copy
or incomplete GSS continuation MUST remain silent terminal
rejection. Do not disclose provider-specific major/minor codes
or emit any success-shaped token on failure.

Capture the active TLS `SSL*`, selected X509 fingerprint and
valid version-6 nego-only DER BEFORE the accepted provider
step; the existing fail-only GSS cleanup clears its own
credential/context and TLS pin on rejection. Recheck the
selected certificate before enqueuing the **fixed**
`STATUS_LOGON_FAILURE` (0xC000006D) to the existing single
`TsRequestTlsReplyWriter`; never introduce a parallel queue,
record cache or SSL writer. A new `FailureQueued` outcome
means the provider is already terminal and exactly one error
reply is waiting for caller-driven TLS writes; it is NOT a
successful SPNEGO result or OS authorization. Writer identity,
pending state, retry pointer, secure wipe and terminal release
remain unchanged. Do not interpret `FailureQueued` as license
to advance to CredSSP authInfo, MCS, console or desktop.

Opt-in genuine provider failure tests MUST use explicit
TERMSRV service, caller-provided FILE:/ keytab and separate
FILE:/ cache, and genuine TLS BIOs. They must not silently
read the host login/keytab, fabricate provider rejection or
claim successful Kerberos authentication from a negative
wire result. Keep the opt-in test inactive in default CI.

## Canonical and terminal CredSSP error replies (2026-10-14)

Per MS-CSSP 2.2.1/3.1.5, only v6 is
supported by the new server fail-only
serializer; the legacy 3/4 error cases
remain unsupported rather than silently
pretending v5 has errorCode semantics.
Represent negative NTSTATUS as exactly
four DER signed INTEGER octets. Permit
ONLY fixed `STATUS_LOGON_FAILURE` and
`STATUS_NOT_SUPPORTED`, not positive
success or provider-specific minor error
leaks. Never mix [4] with negoTokens,
pubKeyAuth, authInfo or nonce.
The original `TsRequestTlsReplyWriter`
must own BOTH success and failure
replies via the same PRIVATE encoded
queue, preserving pending-record
exclusivity, SSL identity, SHA256
selected-certificate continuity, exact
nonblocking write/retry ownership and
secure wipe even when a rejected
candidate reply was already encoded.
A fully delivered failure response
MUST terminate its writer at release;
neither failed nor completed failures
may be used as authenticated identity
or lead to MCS. No automatic provider
error mapping until the true NLA
failure/connection state is implemented.

## Offline finalization role check (2026-10-15; CI PASS)

MS-RDPBCGR 2.2.1.14–2.2.1.21 permits a pure finalization
cross-check using existing exact-length Share Data parsers.
It MUST NOT become a competing state machine, TLS sender
or OS authorization source. Validate role-specific client
channel, server source 1002, share ID, client action and
zero Control IDs, server Cooperate zero IDs, and Granted
user/server channel IDs. The server Synchronize targetUser
is opaque in the published example, not reliable identity.
The caller alone enforces actual wire order, per-message
sender provenance, MCS joins and independent OS admission.
All spans borrow complete input buffers for the call only.

**Exact implementation CI PASS (2026-10-15):**
`27996f24e5fbb497c0bee37756d34551d1a47e47`,
[Actions 38735353873](https://github.com/k1moradi/RDP-server/actions/runs/38735353873).
Linux/GCC **101/101** CTests and macOS/Clang,
Windows/MSVC **91/91** CTests in BOTH Debug and Release,
including the new finalization correlation/denial cases.
SDK consumer/install, ZIP/SHA256 uploads and documentation
policy also PASS; prerelease publishing SKIPPED (no tag).
Owner-local compile, real GSS/TLS positive Kerberos binding,
independent OS authorization and client/desktop remain
**NOT RUN**.

## OpenSSL X.509 continuity through MCS diagnostics (2026-10-15)

MS-RDPBCGR 5.4 and MS-CSSP 3.1.5 require TLS before the
CredSSP authentication/binding flow. The selected certificate
is security-relevant input, not interchangeable merely because
`SSL*` is unchanged. Reuse the existing selected-certificate
SHA-256 routine and compare its bytes with `CRYPTO_memcmp`
before each direct `SSL_read_ex` MCS callback. Do NOT include
OpenSSL's broad ssl.h transitively in portable public headers.
The sole connection owner stores a fixed 32-byte pin, wipes it
on close, and never owns the SSL/BIO or introduces a second
session or identity authority. Certificate continuity does
not authenticate a user or admit an OS account; only a future
trusted GSS and separately authorized OS path may do that.
Plaintext synthetic MCS intake has no live transport provenance.

## General capability semantics without false negotiation (2026-10-15)

For MS-RDPBCGR 2.2.7.1.1, use the existing exact-length,
counted TS_CAPS_SET envelope parser before interpreting
one fixed 24-byte General set. Keep a single zero-allocation
scan using checked offsets, no duplicate capability cache,
no pointer ownership, and no second activation controller.
Treat the protocolVersion field as required 0x0200;
reject duplicate General sets, undersized/oversized
layouts and non-Boolean refresh/suppress bytes. Ignore
pad2OctetsA even when nonzero. Preserve raw OS and
extraFlags advertisement including unfamiliar future
bits, and do not infer any graphics codec or authentication.
Do not strengthen the common generic decoder to reject
other capability lists: other unimplemented features
remain opaque until independently negotiated after
GSS/TLS and OS approval.

**Exact-head CI PASS (2026-10-15):**
`3625b0daadef1f470bc0b23b3b2aff9106750a6a`,
[Actions 38742975505](https://github.com/k1moradi/RDP-server/actions/runs/38742975505).
Linux/GCC **105/105** and macOS/Clang, Windows/MSVC
**95/95** CTests passed in BOTH Debug and Release,
including both new General capability cases. Installed
SDK consumer, ZIP/SHA256 package uploads and policy
PASS; no version tag, so prerelease SKIPPED.
**NOT RUN:** owner-local new-head build, genuine GSS/TLS
positive proof, independent OS authority, Microsoft
client or graphics/desktop.

## Strict Bitmap capability without inferred authority (2026-10-15)

MS-RDPBCGR 2.2.7.1.2 requires bitmapCompressionFlag
and multipleRectangleSupport to equal one for a
connection to proceed. Parse their LE16 values only
AFTER the existing exact Active/capability envelope
gate; require a single 28-byte Bitmap set, nonzero
desktop dimensions and valid Boolean resize flag.
Treat preferred color depth and drawing flags as raw
advertisements, not negotiated/OS-authorized output
settings. Ignore padding, legacy 1/4/8-bpp client
receive fields and highColorFlags, even if nonzero,
rather than rejecting valid Microsoft peers.
Do not use the advertised dimensions as a memory
allocation size. Preserve unknown siblings, make
no state copies and add no second session owner.

**Exact implementation CI PASS (2026-10-15):**
`89ffef98b4f27ad2947b4629c9eefa49b64152a7`,
[GitHub Actions 38746309146](https://github.com/k1moradi/RDP-server/actions/runs/38746309146).
Linux/GCC **107/107** and macOS/Clang,
Windows/MSVC **97/97** full CTests each in BOTH
Debug and Release. New
`transport.share-bitmap-capability-wire`
and `transport.share-bitmap-capability-rejections`
PASSED on each system; documentation-policy,
installed SDK consumer, ZIP/SHA256 packaging/upload
PASSED. Untagged prerelease SKIPPED.
**NOT RUN:** owner-local single-build-root compile,
real GSS/Kerberos/TLS binding, independently approved
OS session, licensed capabilities, graphics or desktop.

## Keep connected TCP/BIO provenance through MCS (2026-10-15)

A borrowed `SSL*` or a completed handshake alone
does not establish it is attached to the same TCP I/O
that received X.224. Pin both the selected `SSL*`
and its shared read/write BIO on a successful
`attachTlsTransport`. Reject duplicate attach,
swapped SSL, swapped BIO or `BIO_get_data` retargeting
before any `SSL_do_handshake` or `SSL_read_ex`
from the connection-oriented readiness callbacks.
Never dereference a stored old BIO before confirming
it is STILL the SSL's active read AND write BIO:
`SSL_set_bio` may free the original. Keep all socket
and SSL lifetimes borrowed, event-loop serialized
and non-owning; close the sole preauth diagnostic on
invalid/replayed transitions. Legacy synthetic
TLS fixtures stay available for tests but are not
authenticated/OS-authorized session admission.

**Exact implementation CI PASS (2026-10-15):**
`45f68c2c0fcaa163aaf242a99f5637726a023fe2`,
[Actions 38749371803](https://github.com/k1moradi/RDP-server/actions/runs/38749371803).
Linux/GCC **109/109**, macOS/Clang and
Windows/MSVC **99/99** full CTests each in BOTH
Debug and Release, including the strict connected
TLS ownership/MCS ordering denial cases and
the actual native loopback transport. Documentation
policy, installed SDK downstream consumers, ZIP/SHA256
package uploads PASS. Prerelease SKIPPED (no tag).
**NOT RUN:** owner-local exact-head CTest, real GSS/
CredSSP/TLS binding, independent OS authority,
live authenticated Microsoft RDP client and desktop.
