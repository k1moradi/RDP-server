# CODEX.md — RDP-server agent contract

**No new branches without an explicit request from the repository owner.**
This prohibits all agents, including Codex, from invoking branch creation
(`git switch -c`, `git branch`, `git checkout -b`,
`git worktree add -b`, GitHub branch-create endpoints, or automation).
Work on the existing `main` branch or in a detached worktree for tests.

## Mission

> RDP protocol first. Fast native C++23 implementation. No workarounds when a
> standards-compliant RDP mechanism already solves the problem.

The aim is a standalone, cross-platform, open-source **C++23** RDP server,
not a patched xrdp runtime, VNC bridge or proprietary client shim. Do not
invent new transport, clipboard or graphics semantics if standard RDP
mechanisms exist. Preserve third-party attributions and GPL compliance.

## Correctness and deployment

- The source currently provides a protocol foundation only, not a complete
  installable server. Do not label tests or connection probes "RDP server
  acceptance" without external real-client authenticated desktop verification.
- No host activation, service restart, reboot, live user clipboard read,
  desktop takeover or human interaction without explicit authorization.
- Avoid default rollback backups or service activation script reintroduction.
- Run native C++23 compile, protocol unit tests, and cross-platform
  build checks when making protocol changes.
- Never add an xrdp, chansrv, VNC/RFB or patched upstream C runtime as a
  build dependency. OS-specific adapters are separate modules.
- Record the first failing wire-protocol boundary, keep output truthful,
  and fix code instead of hiding failing tests or forcing merges.
