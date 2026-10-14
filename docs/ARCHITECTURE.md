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
