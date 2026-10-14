# Coding standards — native C++23 RDP server

**Mandatory on every agent prompt:** [AGENTS.md](AGENTS.md),
[VISION.md](VISION.md), the [living TODO](docs/ROADMAP.md), and the
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
