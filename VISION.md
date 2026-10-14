# RDP-server — canonical project vision

## Mission

Build a fast, secure, interoperable, open-source **C++23 Remote Desktop
Protocol server** across Linux, macOS, Windows, BSD and other operating
systems, using a portable RDP core and replaceable OS integrations.

> RDP protocol first. Fast native C++23 implementation. No workarounds when a standards-compliant RDP mechanism already solves the problem.

## Product acceptance

- **Independence:** No runtime or build reliance on xrdp, VNC/RFB,
  patched chansrv or another RDP server. Historical sources are
  provenance, not protocol architecture.
- **Protocol:** Complete standards-compliant X.224/TPKT, MCS/GCC, TLS,
  CredSSP/NLA, licensing, capabilities, share activation, virtual
  channels, graphics, input and orderly disconnect/reconnect.
- **Security:** Explicit negotiated identity, independent OS session
  authorization, bounded untrusted input and deterministic cancellation.
- **Portability:** C++23 first-party wire/session core and separable
  capture, input, clipboard, credentials and platform session adapters.
- **Usability:** Windows and macOS clients and FreeRDP clients can connect
  securely and use a real desktop with graphics, input and CLIPRDR
  text, PNG/DIB and standard file clipboard. No mandatory FUSE mounts.
- **Efficiency:** Low CPU, RAM, bandwidth and tail latency on old
  hardware; scalar baseline, measured optional acceleration.
- **Sustainability:** One state-machine owner, shared reusable tests,
  one reusable build root and minimal duplicated documentation.

## Current truthful status (October 14, 2026)

A subset of first-party C++23 files is migrated and a portable static
protocol library passes historical cross-platform tests. It is **not**
an authenticated or installable standalone RDP server. The full former
project was not migrated, and its automated source-import workflow has
been retired. Do not mistake green protocol unit tests for client
acceptance, real desktop admission or performance.

## Execution model

Implement a bounded client-facing RDP connection state machine, authenticated
session and channel lifecycle, then graphics/input/clipboard integrations
and OS adapters. Accept each milestone only with negative tests and
appropriate real-client evidence. No production access from synthetic
security fixtures.

The one living TODO is [docs/ROADMAP.md](docs/ROADMAP.md).
Mandatory standards:
[coding](coding_standards.md), [testing](testing_standards.md),
[compilation](compile.md), [benchmarks](benchmark.md).
All agents follow [AGENTS.md](AGENTS.md) on every task.
