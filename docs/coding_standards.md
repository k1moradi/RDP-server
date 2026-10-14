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
