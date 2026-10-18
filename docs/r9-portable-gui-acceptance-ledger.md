# R9 portable GUI distribution and acceptance ledger

Baseline: `7f7f6b0dc5d5c47117b0fdf4cf223d54e547af91` (primary Actions 39157893314, independent structure 39157893350). These baseline runs passed; the baseline artifact list contains `rdp-server-gui-linux`, but no separately downloadable Windows or macOS PORTABLE-GUI archives.

## R9 CI publication correction

The Windows CLANG64 packaging lane already builds and verifies a PE/DLL-closure checked x86_64 ZIP, then performs an extracted, path-with-spaces, offline GUI smoke. The macOS arm64 lane already builds, checks Mach-O closure and extracted ad-hoc signature, and performs an extracted Cocoa launch. Upload the ZIP and its SHA256 file only after the corresponding native smoke passes. Linux keeps the separately named `rdp-server-gui-linux` artifact and Linux/XCB extract/launcher preflight. These are portable GUI previews, not protocol SDK packages or startup-disabled SERVER-TEST archives.

Each candidate artifact must retain its full source SHA manifest, outer SHA256, licenses/notices, architecture, and dependency inventory. Do not claim Windows/macOS artifacts are available until a **new exact-SHA CI run** succeeds and lists them. Do not substitute hosted package checks for owner-native Debug/Release evidence. macOS ad-hoc preview signing is **not** Developer ID distribution or notarization.

The R3 DVC sanitizer selector must remain exactly **20** registered cases including `transport.dvc-graphics-frame-credit-preflight`; R8 clipboard component sanitizer selector remains exactly **87** and separately asserts native bridge/linkage source guards. R4 surface geometry, R2 IPv4-mapped IPv6 admission quota, R7 Qt client stage, and R8 stable scalar clipboard receipt require exact-HEAD CTest inventory verification; a general green matrix alone does not prove focused selection. Do not lower a pinned count to disguise changes.

## Physical/owner acceptance ledger — NOT RUN

| Acceptance gate | Status | Required evidence |
|---|---|---|
| GUI-only existing OS-account setup, authorization and seat0 owner | NOT RUN | Real logged-in owner/session receipt, no synthetic permission |
| LAN Start / Stop, no unauthorized side effects | NOT RUN | GUI action and socket/firewall before/after evidence |
| Microsoft-client CredSSP and Share | NOT RUN | Real mstsc/Windows App handshake and protected admission |
| First video frame and FRAME_ACK | NOT RUN | Correlated server/client frame ID and accepted-byte/ACK receipts |
| Keyboard/mouse input | NOT RUN | Genuine owner-authorized input and revocation |
| Resize / surface recovery | NOT RUN | Client-driven resize with surface retirement and new valid frame |
| Disconnect / Stop / exit / rerun | NOT RUN | Native lifecycle and zero post-retirement callback evidence |
| Offline-LAN operation | NOT RUN | Disconnected-from-Internet real LAN client run |
| M1 Linux/X11 owner-native Debug | OPEN | Same candidate SHA, owner hardware/toolchain, full CTest |
| M1 Windows MSYS2 CLANG64/Clang23 owner-native Debug | OPEN | Same candidate SHA, owner hardware/toolchain, full CTest |
| M1 macOS 27 owner-native Debug | OPEN | Same candidate SHA, owner hardware/toolchain, full CTest |

No candidate freeze before R10 nominates a single SHA. Hosted successes cannot advance any NOT RUN row.
