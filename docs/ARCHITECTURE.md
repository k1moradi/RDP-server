# RDP-server architecture

**Armada:** RDP protocol first. Fast native C++23 implementation. No
workarounds when a standards-compliant RDP mechanism already solves the problem.

## Module boundaries

```text
Windows App / Microsoft Remote Desktop / FreeRDP / other RDP clients
                         │
           TLS + CredSSP/NLA + X.224/TPKT
                         │
               MCS/GCC and RDP session
                         │
              RDP virtual-channel router
                   ┌─────┼─────┐
             graphics  input  CLIPRDR and channels
                   └─────┼─────┘
                 platform abstractions
       ┌───────────────┼──────────────┐
     Linux           macOS         Windows/other OS
```

The diagram is the **target**, not an implemented daemon. Source-owned
foundation APIs currently reside in `src/server/transport`,
`src/server/security`, `src/server/clipboard`,
`src/clipboard`, `src/core` and `src/rdp`.
`src/x11` contains Linux/X11-specific adapter candidate code: it is not a
portable dependency of the protocol archive. Other imported algorithms not
listed in CMake are under porting review and are not silently shipped.

### Independence test

The top-level CMake project enables **CXX only**, targets C++23, and links
only the maintained first-party protocol sources, C++ runtime and
OpenSSL. Its build must not discover or compile upstream xrdp or VNC.
The protocol static archive must not open a listening socket or claim
to be a complete server.

### Implementation principles

- Portable wire parsers reject malformed lengths/flags and ambiguous states.
- No trusted-client assumptions for inputs from RDP channels.
- Generation-aware clipboard request/response serialization; no unsolicited
  image forwarding, no fake file objects.
- OS adapters handle session selection and desktop capture without contaminating
  RDP protocol state.
- Strict tests, sanitizers and real-client gates before release.

### Current connection intake boundary

The portable `PreauthConnectionStream` extends the existing
`PreauthSession` and X.224 parser with bounded TCP byte-stream intake.
It consumes **only** the initial plaintext Connection Request, returns
the exact consumed bytes, and produces the existing TLS-negotiation
Confirm or failure decision. A transport adapter must send the entire
response before starting TLS and leave already-received TLS bytes
unconsumed. This is **not** an active TCP listener, a TLS provider,
an authenticated RDP session or a connection to a desktop.

The stream owner additionally enforces send-before-TLS ordering:
an adapter must report a **single successful full X.224 response
write** before the diagnostic TLS transition is permitted. Failed,
premature or duplicate completion closes it. This guards the future
transport adapter contract but does not implement that adapter.

### Incremental decrypted Basic Settings Exchange intake

The **same** `PreauthConnectionStream` now reuses one fixed-size
8,192-byte buffer for the initial CR (at most 260 bytes) and for
decrypted MCS Connect Initial after the diagnostic TLS transition.
The TPKT length is checked before accumulating the body and the
X.224 Data TPDU is checked before buffering BER. The parser receives
exactly one complete bounded frame; extra decrypted bytes remain
unconsumed. After validating or rejecting its GCC content, the
diagnostic closes. The API neither negotiates genuine TLS/NLA nor
emits an MCS response or authorizes an OS session.

### Build/install/release boundary

The protocol static library has an installable CMake target
`RDPServer::protocol`, an OpenSSL-aware package config, and
cross-platform CPack ZIP archives. GitHub Actions builds both
configurations and checks a separate downstream consumer before
uploading CI artifacts. An authorized matching version tag can
publish a GitHub **protocol SDK prerelease**. This is an artifact
delivery mechanism only: it does not introduce an RDP listener,
service installation, authentication or desktop deployment.

### Real TLS handshake evidence boundary

Before the one-owner preauth stream progresses from X.224 to decrypted
MCS, it now requires a **completed OpenSSL server SSL session**
(TLS 1.2+, negotiated cipher and selected server certificate), not
merely a Boolean callback. Test transport uses an in-memory BIO
pair and a temporary self-signed test certificate. A future
socket adapter must retain the live SSL object and handle all
encrypted I/O, send acknowledgments, shutdown and cancellation.
No network listener, CredSSP/OS identity, real desktop or
MCS Connect-Response is created by this offline increment.

### Bounded TLS application-data intake (2026-10-14)

After the complete X.224 Confirm write and a verified live server TLS
handshake, the existing preauth owner retains only the **identity of a
borrowed SSL** handle, cleared on terminal close. The new
`consumeMcsConnectInitialFromTls` reads at most 8,192 bytes through
OpenSSL `SSL_read_ex`, requesting only the remainder of the
4-byte TPKT header, 3-byte X.224 Data TPDU, or declared MCS frame
at a time. OpenSSL retains coalesced plaintext for a later consumer;
the diagnostic does not accept that extra packet. WANT_READ/WRITE are
retryable; close_notify, provider errors, wrong SSL identity and
invalid framing terminate. No extra session state authority,
network listener, MCS response or OS admission exists.

### Byte-accurate X.224 Confirm/Failure output (2026-10-14)

The existing preauthentication stream now owns precisely one 19-byte
X.224 negotiation response and exposes only the unsent suffix.
A nonblocking transport must report the **actual** positive number
of bytes accepted from that suffix; zero means retry on writable
readiness. A short write cannot advance the TLS handshake. On
`RDP_NEG_FAILURE` the same stream permits the entire failure
response to drain, then closes; on `RDP_NEG_RSP` it permits TLS
only after every byte has been acknowledged. Hard socket failures
abort the stream. This is a portable I/O boundary, not an
active network listener, TLS credential verifier or OS admission.

### Nonblocking native X.224 socket boundary (2026-10-14)

`PreauthTcpAdapter` contains one preauthentication owner and a
borrowed `TcpNonblockingIo` adapter. The platform-native
`NativeTcpIo` delegates to recv/send (Winsock or POSIX) without
binding, listening, owning a socket or activating any service.
The caller must create an already-connected nonblocking socket,
drive readable/writable readiness on a single event loop,
and configure SIGPIPE handling where required. The adapter reads
exactly the missing TPKT header/body bytes, leaving any early TLS
ClientHello record in the native TCP buffer. It drains the existing
19-byte RDP_NEG_RSP/RDP_NEG_FAILURE on writability, then signals
ready-for-TLS or terminal close. It cannot establish a TLS session,
authenticate an OS identity or construct an MCS domain.

### One-owner nonblocking OpenSSL handshake progression (2026-10-14)

Once X.224 Confirm has been fully sent, the existing
`PreauthConnectionStream` can drive one server-side
`SSL_do_handshake` per event-loop readiness callback.
WANT_READ and WANT_WRITE return independently; the stream
binds the borrowed SSL identity on the first attempt and
refuses swapping it during a partially complete handshake.
A successful provider handshake passes the existing TLS 1.2+,
certificate, cipher and server-role gate; the SAME SSL then
decrypts the initial bounded MCS/GCC PDU. Fatal TLS errors and
cancellation close the sole preauth owner. `PreauthTcpAdapter`
forwards this readiness call without a second state machine.
The socket/BIO still belongs to the caller; no socket listener,
certificate enrollment, CredSSP, MCS response or OS admission
is added in this increment.

### Borrowed nonblocking native socket BIO and TLS loopback (2026-10-14)

The native `PreauthTcpAdapter` and the same protocol owner now
cross the previously synthetic TLS/network boundary. An OpenSSL
custom `BIO_METHOD` delegates encrypted record read/write to the
existing `TcpNonblockingIo` rather than using platform-specific
`SSL_set_fd` integer casts. It reports SSL WANT_READ/WANT_WRITE on
would-block, and ordinary EOF/error on closed/failed I/O; `SSL`
owns/free the BIO, while the external caller owns the already
connected nonblocking socket and its IO object. The BIO neither
copies/owns the socket nor creates a second RDP state controller.
Attaching on the server adapter requires completion of X.224
Confirm output. The same SSL then drives server handshake and the
existing bounded MCS/GCC diagnostic. A test-only listener binds
to 127.0.0.1 port 0, accepts one peer and closes the listener
before TLS; no installed daemon or persistent listening service.
Credential verification, OS identity and MCS server response remain
unimplemented.

### T.125 Connect-Initial domain parameter negotiation (2026-10-14)

The existing MCS/GCC parser and **same** preauthentication diagnostic
now apply the eight-field `MergeDomainParameters` rules from
[MS-RDPBCGR 3.3.5.3.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7617f746-95c9-4a6e-808d-e2f642471e86)
after a complete decrypted Connect-Initial and before treating
the envelope as validated. Channel/user counts, token IDs,
priorities, throughput, height, max PDU size and protocol version
are merged from client target/min/max sets; the result is a
**value only** and neither allocates channels nor creates
an MCS domain. BER decoding accepts syntactically valid minimum
and maximum protocol-version integers, while negotiation still
requires effective version 2. On merge failure the existing
preauth owner closes as before. No Connect-Response, CredSSP
account identity, OS authorization or desktop is produced.

### Offline MCS Connect-Response/GCC serializer (2026-10-14)

After a checked MCS Connect-Initial, the portable first-party
`encodeMcsConnectResponse` independently revalidates the client's
GCC settings and T.125 merged DomainParameters, then builds
a complete bounded wire PDU: RFC 1006 TPKT, Class 0 X.224 Data,
BER APPLICATION 102 Connect-Response with success result and
calledConnectId 0, followed by a T.124 GCC ConferenceCreateResponse
with the H.221 server key `McDn`. The response holds the server
Core block (RDP 5 compatible version, offered SSL), Network block
(I/O channel 1003 and explicitly supplied, nonduplicated channel IDs
with the correct odd-channel pad) and Enhanced Security block
(encryption method and level zero, no legacy RC4 key or certificate).
All BER/PER lengths are derived from the actual payload, and
failure produces an empty packet. The published Microsoft example
[MS-RDPBCGR 4.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3)
provides the independent wire oracle for the common layout.

**Crucial authority boundary:** this is an OFFLINE encoder, not a
preauthentication state transition and not permission to send
rt-successful on a live connection. The existing owner still
closes after diagnostic MCS intake. No TLS record emission,
CredSSP, OS session or MCS domain/channel lifecycle was enabled.

### Pure PER MCS Channel Connection request decoding (2026-10-14)

The first-party `mcs_channel_connection.{h,cpp}` adds a pure,
non-allocating request decoder for MS-RDPBCGR 2.2.1.5 (Erect Domain),
2.2.1.6 (Attach User) and 2.2.1.8 (Channel Join). It reuses the
existing exact TPKT/X.224 Data TPDU validator and decodes the T.125
aligned BASIC-PER discriminator and fields into a *value only*.
Erect accepts canonical 1..4 octet nonnegative subHeight and
subInterval. Attach has no payload beyond its one-byte type.
Join extracts the PER UserId offset (wire value plus 1001) and
channelId without treating that as evidence of allocation.

This does not change `PreauthConnectionStream`'s existing terminal
diagnostic behavior after Connect-Initial. It does not accept a
user identity, mutate an MCS domain, join a channel, decrypt
additional PDUs, send replies or create a server listener.
Those transitions require a separately verified authentication
and OS session authority, which remains unimplemented.

### Offline T.125 server Attach User/Channel Join confirmations (2026-10-14)

The existing first-party `mcs_channel_connection` portable module
now encodes the T.125 aligned-PER **server** responses specified
in [MS-RDPBCGR 2.2.1.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3b3d850b-99b1-4a9a-852b-1eb2da5024e5)
and [4.1.8.2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7443e65e-3482-4cec-823a-741eb1fe27b4).
For an externally provided assigned user, the 11-byte Attach
User Confirm carries its PER UserId offset. The 15-byte Channel
Join Confirm is conditional on a decoded Join Request with the
same assigned user and requested channel that occurs once in
a bounded external allocation list; it repeats the confirmed
channelId. Both return fixed-size values only, with no retained
pointers, domain mutations or SSL writes. These are *offline*
wire primitives, NOT a server acceptance gate. The existing
preauthentication stream still closes after the Connect-Initial
diagnostic; an actual OS authentication/authorization provider
and one authoritative MCS owner remain essential before any
success packet may be transmitted.

### Offline T.125 MCS Disconnect Provider Ultimatum (2026-10-14)

The existing `mcs_channel_connection` module now provides an
allocation-free, fixed-nine-byte TPKT/X.224/T.125 PER
Disconnect Provider Ultimatum encoder matching
[MS-RDPBCGR 4.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/19a238a5-0455-46f0-a96b-31320d9a70a1).
Per [3.1.5.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3efcb3f7-8fa5-488b-8388-bf4d32004b8c),
only provider-initiated (1) and user-requested (3) can be
serialized by the server. The existing bounded parser recognizes
a complete Disconnect Provider Ultimatum and rejects invalid
TPKT/X.224 and PER padding, but ignores even reserved inbound
reasons as mandated by
[3.1.5.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f10e972d-7b77-4fa5-999f-08406fe86284).

These pure helpers do not grant session/OS admission, encrypt,
send data, close a transport, or duplicate lifecycle ownership.
A future authenticated connection owner must send the entire PDU
via its negotiated TLS/security transport and then close.
Offline tests cannot establish live client disconnect semantics.

### Offline T.125 client MCS Send Data Request (2026-10-14)

The existing `mcs_channel_connection` module now parses T.125
SendDataRequest (DomainMCSPDU choice 25) after exact TPKT/X.224
envelope validation. As specified in MS-RDPBCGR 4.1.16,
the request contains an initiator UserId offset from 1001,
a 16-bit channel ID, two-bit priority and segmentation values,
zero padding, and an aligned-PER OCTET STRING userData field.

The decoder accepts 7-bit and 14-bit PER length encodings, including
two-octet lengths for small payloads as emitted by real RDP stacks.
Fragmented PER length determinants are rejected; userData is
limited to 16383 bytes in a single complete TPKT. Returned userData
is a borrowed read-only span into the caller-owned input: the caller
must retain its backing bytes until synchronous use completes.
No copies, heap allocations or competing connection controllers.

The result is a syntax-only building block. It does NOT establish
TLS provenance, authentication, joined channel membership, complete
segmented application data, virtual channel routing or remote desktop
admission. Existing preauthentication diagnostics still close before
any live post-channel MCS traffic. A future authorized single session
owner must independently validate the assigned user and joined channel
before consuming the borrowed payload.

### Offline server MCS Send Data Indication encoder (2026-10-15)

The current first-party `mcs_channel_connection` module now writes
T.125 server-to-client `SendDataIndication` (DomainMCSPDU choice 26,
0x68), per
[MS-RDPBCGR 1.3.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee)
and
[2.2.6.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/6c074267-1b32-4ceb-9496-2eb941a23e6b).
A caller-owned `std::span<std::uint8_t>` receives one exact
TPKT/X.224/aligned-PER server frame. The fixed fields are
initiator UserId offset by 1001, channelId, dataPriority,
segmentation, 7-bit or 14-bit PER userData length and
caller-provided opaque bytes (up to 16383). All bounds,
UserId range, nonzero channel, priority and segmentation
are checked before ANY output mutation. Short length is
chosen for 0..127 bytes, long length for 128..16383.
The packet is written with one overlap-safe payload move
followed by header stores, without internal heap allocation;
unwritten output suffix is unchanged.

This is an OFFLINE serializer, not an authorized server
data path: the future single authenticated domain owner must
prove the assigned user and joined channel, supply a valid
inner RDP/licensing/virtual-channel PDU and complete TLS
encryption/transmission. The encoder itself performs no SSL
I/O, session admission, OS operation, reassembly or graphics.

### Offline RDP connection-finalization Control and Synchronize PDUs (2026-10-15)

The original `mcs_channel_connection` module now reuses its checked
Share Control and Share Data decoders to parse two *finalization*
payloads. Per
[MS-RDPBCGR 2.2.1.14.1](https://learn.microsoft.com/fr-ch/openspecs/windows_protocols/ms-rdpbcgr/3fb4c95e-ad2d-43d1-a46f-5bd49418da49),
`TS_SYNCHRONIZE_PDU` is exactly 22 bytes including
the 18-byte enclosing headers, type2 `0x1f`, little-endian
`messageType=SYNCMSGTYPE_SYNC (1)` and an uninterpreted
`targetUser` channel ID. Windows Server's documented
`STREAM_UNDEFINED=0` exception remains supported by the
underlying Share Data decoder. Per
[MS-RDPBCGR 2.2.1.15.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/0448f397-aa11-455d-81b1-f1265085239d),
`TS_CONTROL_PDU` has exactly 26 bytes including headers,
type2 `0x14`, little-endian `action` 1..4 (Request,
Granted, Detach, Cooperate), `grantId` LE16 and
`controlId` LE32. Source/share IDs are carried from
the checked enclosing frame. Wrong kind, total length,
nested length, unknown action, invalid messageType,
and unsupported compressed payload fail without
exposing or applying any action. Pure C++23, no copies,
allocations, state machine or extra decoder owner.

Microsoft's decrypted Client Synchronize, Client
Cooperate, Client Request and Server Granted Control
fixtures are independently checked in the existing
MCS behavior registry. The **real** finalization protocol
imposes DIRECTIONAL rules that pure syntax cannot
prove: Client Request/Cooperate have zero grant/control
IDs, while Server Granted uses a previously assigned
user-channel ID and server channel ID. The parser
intentionally preserves raw IDs and actions, including
a potentially forged client-side Granted enum, WITHOUT
calling any state transition. Only one future *genuinely
CredSSP/Kerberos TLS-bound and independently OS-authorized*
session owner may validate direction, assigned channel,
share ownership, ordering, licensing and capability
negotiation before advancing or granting control.
This still does not enable live TLS, input or desktop.

### Offline uncompressed Share Data Header decoding (2026-10-15)

The original first-party `mcs_channel_connection` module now exposes
`parseRdpShareDataHeader`, layered on its *existing*, exact-length
`parseRdpShareControlHeader`. Under
[MS-RDPBCGR 2.2.8.1.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4b5d4c0d-a657-41e9-9c69-d58632f46d31),
a Data PDU contains a further 12-byte Share Data Header: LE32
shareID; ignored pad1; streamID; LE16 uncompressedLength;
pduType2; compressedType; and LE16 compressedLength.
Only the 24 documented pduType2 values are recognized.
STREAM_UNDEFINED (0) is permitted ONLY for Synchronize
because the Microsoft specification identifies a known
server compatibility exception; streams 1/2/4 are standard.

Some real Client Font List packets carry uninitialized
`uncompressedLength`. Keep it as reported metadata, NEVER
allocate from it or equate it to the already-validated Share
Control `totalLength`. Ignore pad1 even if nonzero. Keep
`compressedLength` as reported metadata when uncompressed.
Every nonzero `compressedType` is explicitly UNSUPPORTED:
no compressed payload is exposed to downstream application
processing until an authenticated owner has a correctly
negotiated and bounded bulk decompressor/history.
The returned body is an allocation-free, read-only borrowed
`std::span` into caller-owned complete input, beginning
after the full 18-byte Share Control + Share Data header.

This is OFFLINE syntax, not an MCS/OS admission decision,
security-header detector, capability negotiation, nested
Share Control/INPUT/COLOR decoder, licensed session,
graphics pipeline or live RDP server. Microsoft Control,
Font List and Font Map examples provide independent wire
oracles; real-client acceptance remains separately gated.

### Offline RDP Share Control Header decoding (2026-10-15)

The existing portable `mcs_channel_connection` translation unit now
decodes an explicitly isolated six-byte T.128 `TS_SHARECONTROLHEADER`
per [MS-RDPBCGR 2.2.8.1.1.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/73d01865-2eae-407f-9b2c-87e31daac471).
Its little-endian `totalLength` must match the entire supplied Share
Control PDU, its 12-bit protocol version must be `TS_PROTOCOL_VERSION`
(1), and the low four bits must designate Demand Active (1),
Confirm Active (3), Deactivate All (6), Data (7), or Server
Redirection (10). The server must ignore `totalLength=0x8000`
(T.128 FlowPDU); it is returned as a distinct ignored status
without a body or ordinary PDU success.

The decoded source ID is syntax only, not verified channel ownership.
The remaining PDU bytes form a read-only `std::span` borrowed
from the unchanged caller-owned complete Share PDU. No allocation,
data copy, nested PDU processing, decompression, or TLS/socket I/O.
The existing MCS parser can supply a borrowed `userData` span,
but **not every MCS userData payload is a Share Control PDU**.
The sole future authenticated owner must first validate MCS channel
membership, actual security-header presence/meaning, licensing
or client-info phases, segmentation/reassembly, and the Share
Control message boundary before using this parser. In particular,
this change does not admit share activation, client keyboard/input,
graphics, OS accounts or remote desktop sessions. The published
26-byte Microsoft Server Control example provides an independent
header oracle; tests do not claim end-to-end server interoperability.

### Bounded decrypted CredSSP TSRequest framing (2026-10-14)

The existing first-party CredSSP DER parser gains
`TsRequestFrameReader`, a fixed-capacity framing helper,
**not** an RDP session, GSS mechanism, login controller or
TLS event loop. Following the MS-CSSP 2.2.1 TSRequest DER
SEQUENCE length, it takes at most one complete decrypted
TSRequest per call and counts exactly how many bytes of the
supplied plaintext were consumed. It handles callbacks split
at any header or payload boundary without swallowing the
next coalesced frame. It validates canonical short/long DER
lengths before accepting the body, enforces the existing
16 KiB ceiling and invokes `parseCredSspTsRequest` at
completion. The borrowed full-frame view exists only until
explicit `releaseFrame`, terminal rejection, close or
destruction, which zeroes the stored ciphertext.

This component does not change the diagnostic's
`PROTOCOL_SSL` security selection; no CredSSP packets are
accepted over a live connection and no session is admitted.
Future GSS authentication must consume this DER synchronously,
verify binding and independently validate OS account/console
authorization before an MCS state transition can occur.

### Offline CredSSP server TSRequest DER serializer (2026-10-14)

The existing portable CredSSP parser/framer also exports a bounded,
single-reply DER serializer for MS-CSSP 2.2.1 `negoTokens` and
already-encrypted `pubKeyAuth` (versions 5/6 only). It writes one
minimal definite-length SEQUENCE and validates size before any
one-shot vector allocation; empty or over-limit provider output
fails without bytes. The payload is opaque and remains the provider's
responsibility; this library cannot determine Kerberos success,
encrypt its own public-key hash, authorize OS identity, send a
TLS record or transition to MCS. Test vectors are synthetic and
no authentication grant exists.

### Linux GSSAPI provider compilation and framed-token handoff (2026-10-14)

The optional `rdp-server-linux-gssapi` build target links the
first-party GSS SPNEGO acceptor, protected-binding and
deny-only credentials source to the platform GSSAPI library.
It is NOT part of the installed portable protocol SDK or
a service; it is compiled only with the explicit Linux
validation flag. The existing per-connection GSS acceptor
synchronously consumes a completed `TsRequestFrameReader`
frame through `acceptFramedNegoRequest`. The provider
receives borrowed tokens only before `releaseFrame` wipes
the fixed DER storage. Unsupported CredSSP versions, early
incomplete handoff, invalid frames or provider rejection
permanently fail the GSS state and close the framer.

This development gate is deliberately rejection-focused
without a real Kerberos keytab, TLS binding or OS-authorized
session. It grants no admission capability and does not
modify the existing PROTOCOL_SSL diagnostic transport.

### CredSSP decrypted-TLS frame boundary (2026-10-14)

`TsRequestFrameReader` now optionally owns the per-connection
TLS read association: `readOneTlsStep(SSL*)` accepts ONLY a
finished server-role OpenSSL session using TLS 1.2+ and a selected
server certificate/cipher, and pins the SSL pointer across frames.
It issues exactly one capped `SSL_read_ex` call per invocation,
reading at most the next TSRequest DER bytes-needed boundary.
`Progress` means OpenSSL may already have additional decrypted
bytes and the connection owner should call again without waiting
for kernel socket readiness. `NeedRead`/`NeedWrite` require
readiness; a complete DER frame blocks all future reads until
explicit secure `releaseFrame()`. No secondary buffer or new
RDP connection/session owner is introduced.
Manual plaintext injection into a TLS-bound reader, or attaching
an SSL stream to a partially manually filled reader, is terminal.
This does not enable CredSSP selection, GSS identity, protected
bindings or OS admission; the current diagnostic still closes.

### CredSSP-to-GSS TLS transcript ownership (2026-10-14)

The single existing `TsRequestFrameReader` owns the TLS
provenance of its currently complete DER frame. A borrowed
`SSL*` can be observed only when that exact frame came
from completed server TLS, never from parser-only DER or a
partially received or released frame. The Linux GSS
acceptor pins that pointer and v5/v6 version on its first
framed negotiation request; subsequent frames cannot
switch certificate/TLS connection or version. The protected
binding handler demands the *same pointer and version*
before GSS unwrap and TLS certificate hash comparison.
Rejection clears the borrowed association; no second
buffer, session owner, or token cache is introduced.
The portable SDK remains independent of GSSAPI; no real
Kerberos authentication, OS session admission or live RDP
listener is enabled.

### Combined final CredSSP SPNEGO and TLS binding (2026-10-14)

Per [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
the client's last GSS token is accompanied by the encrypted
`pubKeyAuth` value (and v5/v6 nonce) in the *same*
TLS-protected TSRequest. The portable parser retains
borrowed spans and performs only field-shape validation.
A Linux GSSAPI method receives the existing completed
TLS-owned frame, requires `ContinueNeeded` and the
pinned SSL/version, accepts the final GSS token and
requires full GSS completion with no extra output token
that a binding-only server reply could not carry.
It then GSS-unwraps/validates the client's hash of
the selected active TLS certificate and nonce, produces
a confidentially GSS-wrapped server hash and releases
the one bounded DER frame. Any failure closes reader
and acceptor; no credentials or OS authorization result
is exposed. Positive live Kerberos and Microsoft-client
acceptance still require separately verified credentials
and independently authorized OS admission.

### Bounded TLS writing of CredSSP server replies (2026-10-14)

MS-CSSP 2.2.1/3.1.5 requires all server negoTokens and
protected pubKeyAuth replies as canonical DER TSRequest
application plaintext inside established TLS. The
existing `credssp_tsrequest` module now provides
`TsRequestTlsReplyWriter`: only the already
tested offline server encoder can produce the one
pending DER frame, with at most the existing 16-KiB
limit. The transport writer borrows/pins the same
completed server-role SSL pointer for its entire
lifetime, owns the stable encrypted-by-TLS plaintext
until `SSL_write_ex` fully succeeds, returns readiness
requirements on real OpenSSL WANT states, and never
replaces or interleaves an outstanding reply. Explicit
release wipes the one pending buffer and keeps the TLS
association for the next provider reply. Terminal
failure and close erase bytes and invalidate identity.
This is transport serialization only, *not* a
second connection/session authority, GSS provider,
proof of Kerberos trust or permission to enable
PROTOCOL_HYBRID, send an MCS domain reply or
admit a desktop session.

### GSS provider-originated server CredSSP replies (2026-10-14)

MS-CSSP 3.1.5 distinguishes server SPNEGO
`negoTokens` responses while a real authenticated
GSS context is CONTINUING, and a server
`pubKeyAuth` response after the final combined
client token and binding has been verified.
The optional Linux `GssapiSpnegoAcceptor`
provides two additional synchronous orchestration
methods using the existing TLS-derived
`TsRequestFrameReader` and bounded
`TsRequestTlsReplyWriter`. It pins the SAME
actual server SSL and v5/v6 version already held
by the provider, verifies that the writer is
idle before consuming another client message,
then calls the REAL MIT GSSAPI context for
provider-originated tokens. The last combined
message requires verified GSS completion,
confidential GSS unwrap, active TLS certificate
binding comparison and server gss_wrap.
Each method queues only a single canonical
server DER response on matching SSL and
erases transient provider vectors immediately.
Invalid stage, missing credentials, synthetic
frame, outstanding reply, GSS provider failure
or mismatch is a terminal close of all three
components. No extra session controller or
portable GSS dependency was added. TLS
queuing alone is not a trusted client, account
authorization or permission to respond to MCS.

### Pin selected TLS certificate across the CredSSP handshake (2026-10-14)

MS-CSSP 3.1.5 requires the client and server to derive their
direction-specific binding hashes from the actual TLS-selected
server certificate SubjectPublicKey and client nonce. An SSL pointer
alone is not a sufficient long-lived certificate identity if
credentials change within the same TLS connection. The existing
first-party `credssp_tls_certificate` module now hashes the
selected, finished TLS 1.2+ server X.509 DER certificate to a
fixed SHA-256 fingerprint, sharing selected-certificate role,
cipher and handshake checks with the SubjectPublicKey binding
computation. The original single bounded
`TsRequestFrameReader` retains this one fingerprint from its
first real TLS read, tests it before every subsequent step,
and hides completed SSL provenance from the GSS provider
if that selected certificate changes even between frame
completion and the synchronous handoff. Secure close
clears the fingerprint; `releaseFrame()` cleanses only
that one DER frame, retaining the transcript identity
for the next request. The fingerprint proves transport
continuity, NOT genuine Kerberos, client OS identity,
account admission or executable desktop availability.

### TLS-owned CredSSP pubKeyAuth binding-only handoff (2026-10-14)

Microsoft MS-CSSP 2.2.1/3.1.5 carries
all client pubKeyAuth ciphertext inside the
same established TLS transcript as SPNEGO.
Previously the optional Linux GSS acceptor's
`processProtectedBinding(SSL*, rawDer)`
could receive caller-injected DER without
proving that those bytes originated from
that SSL stream, notwithstanding its
required verified GSS context. That entry
point is now permanently deny-only.
The existing `TsRequestFrameReader` is the
single TLS provenance + DER lifetime owner
for BOTH the combined-final and binding-only
forms. `processFramedProtectedBinding`
requires its completed server TLS pointer
(and verified selected X509 fingerprint),
the accepted original TLS and v5/v6 version,
exact binding-only DER fields, and the
real Kerberos-secured GSS context before
calling shared confidential GSS unwrap,
active nonce/public-key comparison and
GSS wrap. On success it wipes/releases
the single received DER frame, retaining
the original TLS pin for the next frame.
The new framed reply queue reuses the
existing `queueFramedProtectedReply`
and `TsRequestTlsReplyWriter` rather than
creating another connection state owner.
All failures terminally close and cleanse
frame, writer and GSS context. No evidence
of positive authenticated Kerberos,
OS session authorization, actual RDP
MCS admission or usable desktop is implied.

### CredSSP server TLS outgoing certificate continuity (2026-10-14)

In addition to the existing inbound
`TsRequestFrameReader` TLS certificate
fingerprint pin, the same first-party
`TsRequestTlsReplyWriter` now remembers a
single SHA-256 fingerprint of the
selected, finished server SSL X.509
certificate when it queues its FIRST
canonical v5/v6 TSRequest response.
It validates the identical original
`SSL*` and same selected certificate
at every nonblocking `SSL_write_ex`
attempt (including WANT retry and
already Complete), at explicit
`releaseReply`, and before accepting
any subsequent reply on the same writer.
It reuses the original
`fingerprintActiveCredSspServerTlsCertificate`
instead of maintaining a competing
certificate selection implementation.
Any changed or unhandshaken server
certificate closes and cleanses the
outgoing DER, TLS identity and digest
terminally. Once TLS has accepted a
write, ciphertext may already be on
the wire; rejection cannot retroactively
retract that record and does not count
any future successful write. This
transport boundary does not create
authenticated GSS identity,
independent OS permission or an
RDP server connection controller.

### GSS acceptor transcript-wide X.509 identity (2026-10-14)

The optional Linux real MIT GSS provider is part of the same
TLS/CredSSP transcript but is NOT a second session controller.
Its original pinned `SSL*` and MS-CSSP version are now
accompanied by one independently pinned SHA-256 fingerprint
of the FIRST selected TLS server DER X.509 certificate.
That pin is checked with `CRYPTO_memcmp` on every
subsequent SPNEGO request, protected binding-only or
combined-final proof, before confidential GSS proof
verification, and before queuing a server TLS response.
Recreating the `TsRequestFrameReader` on an unchanged
SSL pointer cannot evade the GSS acceptor's old
certificate identity; terminal reject releases MIT
GSS context and explicit acceptor credential, erases
principal, and cleanses the digest.

An optional Linux-only external-credential test exercises a real
`gss_init_sec_context` initiator using an EXPLICIT
`gss_acquire_cred_from` FILE: credential cache, and the
existing production `GssapiSpnegoAcceptor` using its
independently specified service FILE: keytab.
The real mechanism steps travel inside completed
in-memory OpenSSL TLS application records and canonical
TSRequest DER. Once both sides truly complete, the
test checks confidentially wrapped client-to-server
and server-to-client v5/v6 binding-only public-key
proofs, and a same-SSL certificate replacement
between TWO distinct TLS frame readers. The
binding-only path tests the existing provider seam,
not the REQUIRED combined-last-token MS-CSSP
interoperability with Microsoft Windows App.
No daemon, KDC, OS user admission or desktop
is activated by the test option.

### Explicit GSS provider-rejection to CredSSP v6 error queue (2026-10-15)

The Linux MIT GSSAPI acceptor now distinguishes an actual
`gss_accept_sec_context` provider/policy rejection from a local
frame, version, provenance, keytab, allocation, or TLS pin
failure. Per [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
the server SHOULD provide a negative NTSTATUS when SPNEGO fails
under supported error-code versions. This SDK supports **only v6**
and emits a fixed `STATUS_LOGON_FAILURE` (0xC000006D) via the
*existing* canonical 15-byte `TSRequest.errorCode` serializer
and `TsRequestTlsReplyWriter`.

The new `SpnegoStep.providerRejected` evidence is set only
when the real configured MIT GSS backend has actually processed
a candidate token and rejected its mechanism/security policy.
`acceptFramedNegoAndQueueReply` records the complete v6 TLS-
derived TSRequest, current selected X.509 fingerprint and
continuity of the original SSL before handing it to GSS;
on provider rejection, after provider credentials/context/
principal have already been destroyed, it verifies the
same fingerprint again and queues the canonical negative
reply. It returns `SpnegoStatus::FailureQueued`: **queued, not
written**, and emphatically **not authenticated**. The single
connection owner must drive the existing nonblocking writer's
SSL_write_ex/retry/release path before closing the TLS session.
A completed terminal error does not allow success reply reuse.

Absent explicit keytab credentials, fake caller-supplied DER,
wrong version (v5), changed SSL/certificate, malformed tokens,
failed local copies and pending/wrong writer states still cause
SILENT terminal closure with no errorCode or GSS identity.
The normal CI tests exercise those fail-closed paths, not a
positive credential. The new separate opt-in real-GSS failure
delivery probe requires caller-authorized dedicated keytab
and ticket-cache configuration; it does NOT run in default CI.
Neither the server nor the probe opens an RDP listener, admits
an OS session, or sends desktop data. A genuine full Windows
CredSSP combined-last-token acceptance remains NOT RUN.

### Version-6 CredSSP failure reply transport boundary (2026-10-14)

Microsoft MS-CSSP 2.2.1 and 3.1.5 support a
server `TSRequest.errorCode` on a failed
SPNEGO negotiation at versions 3, 4 and 6.
The existing library currently accepts
only v5/v6 server-reply wire shapes, so
it adds an EXPLICIT, v6-only canonical
15-byte DER failure serializer with
two unsuccessful NTSTATUS codes:
`STATUS_LOGON_FAILURE=0xC000006D`
and `STATUS_NOT_SUPPORTED=0xC00000BB`.
ASN.1 INTEGER must retain its signed
32-bit four-byte representation and
the only populated fields are [0]
version and [4] errorCode. No token,
nonce, credentials or pubKeyAuth is
included. The same single
`TsRequestTlsReplyWriter` now exposes
`queueFailureReply`; both its success-
shaped and fail-only serializer pass
through ONE private guarded queue and
the existing stable OpenSSL retry buffer
and pinned TLS selected certificate.
Only a fully written failure can be
released, after which the writer is
terminally closed; callers cannot queue
a later success. The primitive deliberately
does not auto-generate failure from
a GSS exception: the future session
orchestration must select the correct
stage and sanitized NTSTATUS explicitly,
then reject the session separately.
No new GSS, OS admission, service,
or RDP client acceptance is implied.
