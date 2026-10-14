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
