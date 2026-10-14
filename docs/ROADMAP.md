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
changes; don't create another milestone list. Apply [VISION](../VISION.md)
and the four mandatory [coding](../coding_standards.md),
[testing](../testing_standards.md), [build](../compile.md) and
[benchmark](../benchmark.md) standards. Checkboxes require measured
acceptance evidence; no synthetic completion claims.

### P0 — Preserve work and implement a native RDP server

- [x] Independently compile/test C++23 static protocol foundation;
  historical Actions run 38516048776 succeeded at 77c94c75b467.
  This **is not** a working RDP desktop server.
- [ ] Import all remaining former implementation progress (historical
  source, clipboard experiments, unique development-tip edits and tracked
  local work) from the owner's local checkout per
  [migration instructions](MIGRATION.md). Verify no source loss;
  the old Git history is **not** an import objective.
- [ ] Implement bounded X.224/TPKT/MCS/GCC network listener and complete
  standards-compliant server connection state machine with external-client
  handshake and malformed-packet evidence.
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

- [x] Cross-platform Actions
  [run 38535115706](https://github.com/k1moradi/RDP-server/actions/runs/38535115706)
  passed at `3196a764ffbe24482ad131ad6949f1c2c23d44d9`:
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy jobs.
  Ten semantic protocol CTests and one project-policy CTest are
  registered and passed through the CI jobs. This is **offline library
  and policy validation only**, not authenticated desktop acceptance.
- [ ] Expand reusable sanitizer, parser-fuzz, security-negative and real
  client acceptance suites as native runtime code becomes available.

Each implementation updates the relevant item with exact SHA, test
PASS/FAIL/BLOCKED/NOT RUN, first failing boundary and next smallest step.
Put detailed lessons into the appropriate domain standard, not new files.
