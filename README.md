# RDP-server

**Open-source C++23 implementation of the Remote Desktop Protocol (RDP) server.**

> **RDP protocol first. Fast native C++23 implementation. No workarounds when a standards-compliant RDP mechanism already solves the problem.**

## Mission

RDP-server aims to deliver a fast, secure, interoperable, **standalone,
platform-independent C++23 RDP server**, without requiring xrdp, a VNC/RFB
server, or an existing RDP daemon. Target Windows, macOS, Linux, BSD and other
operating systems through a portable protocol core and OS-specific adapters.

**Current status: under construction — not yet a functional standalone RDP
server.** The previous research and C++23 core live at
[the migration source repository](https://github.com/k1moradi/xrdp-console).
The existing source-owned modules cover parts of X.224/TPKT, MCS, security
negotiation, CredSSP framing, CLIPRDR parsing and graphics policy, but a
complete authenticated RDP listener, desktop backend, input, virtual channel
management, clipboard integration and interoperable end-to-end runtime are
still incomplete. No ready-to-install server is claimed here.

## Architectural rules

1. **Standards before workarounds.** Implement the documented RDP capability
   negotiation, protocol state machines and server channels; reject malformed
   traffic and unsupported mechanisms explicitly.
2. **Native C++23.** The server implementation and protocol code belong in
   maintained C++23 source. OpenSSL, native OS frameworks and standard
   system security APIs may be used as dependencies; an xrdp or VNC runtime
   must not be a dependency.
3. **Portable core, replaceable platform adapters.** Keep transport, RDP
   framing, authentication flow, graphics codecs, clipboard and input protocol
   independent of operating-system capture and input APIs.
4. **Secure by default.** Validate bounds and identities, require suitable
   authentication and encryption, and never advertise a debug probe as a
   production-ready listener.
5. **Measurable performance.** Minimize copies, allocations, latency and
   unnecessary encoding; test client compatibility and difficult network
   and clipboard conditions.
6. **Honest acceptance gates.** Passing unit or loopback tests does not mean
   a complete Microsoft/FreeRDP-compatible, usable desktop server.

## Protocol delivery plan

| Layer | Target | Current acceptance |
| --- | --- | --- |
| X.224 / TPKT / MCS / GCC | Fully interoperable session negotiation | Partial C++23 core only |
| TLS / NLA / CredSSP | Authenticated and identity-bound server sessions | Partial building blocks |
| Licensing, capabilities and share control | Standards-compliant post-auth session | Not complete |
| Graphics | Classic bitmap, RDPGFX and negotiated codecs | Reusable algorithms exist, not integrated server |
| Input | Keyboard, pointer and keyboard layout | Not integrated |
| Clipboard (CLIPRDR) | Unicode, PNG and DIB, including macOS screenshot to browser `File` | Wire-format/transfer work exists; acceptance not met |
| Other virtual channels | Lifecycle, dynamic channel routing, optional device services | Not complete |
| OS integration | Separate backends for Linux, Windows, macOS, others | Not complete |
| Packaging and release | Self-contained installs without xrdp/VNC | Not complete |

See [the architectural charter](docs/ARCHITECTURE.md) and
[migration and acceptance plan](docs/ROADMAP.md).

## License and credits

The first-party project is GPL-3.0-or-later. All reused third-party code
must preserve its original notices and compatible licensing. The project
traces historical upstream-derived work transparently; code origin is not
the same thing as a runtime dependency.

## Branch policy

No new branches may be created by assistants or automated agents unless the
repository owner explicitly requests them. Develop on the existing
`main` branch until otherwise instructed.
