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
