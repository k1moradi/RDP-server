## R5 P1 — authorized graceful held-input cleanup vs terminal retirement (2026-11-01)

**Refreshed shared-main parent:** `5471eb9b649cf1705b56705d0944d95692b12c0d`. The originally assigned aggregate
implicit-destruction gap with both a held keyboard key and a held mouse button
is already closed by production-backed Xvfb coverage, and current main also
contains separate explicit authority-loss and in-flight XShm callback retirement
coverage. Source/dependency review found no production R5 defect that would
justify changing native behavior for the owner's pre-NTLM-Type-3 Windows App
failure.

One independent aggregate boundary was still only exercised at the constituent
XTEST-controller level: the explicitly **still-authorized** graceful
`X11DesktopResources::disconnect()` path. New ordinary
`x11.desktop-resource-graceful-disconnect-held-key-button-release-once` drives one key and one button through the real aggregate
input child under disposable Xvfb, counts actual production XTEST calls,
requires exactly one key release and one button release from graceful
disconnect, and proves repeated disconnect plus implicit destruction add no
duplicate posts. It also requires closed original XCB ownership, retired
XShm/XDamage/capture provenance, no inherited held bookkeeping or Damage,
stale-generation denial and a working fresh replacement capture. This is the
deliberate opposite of terminal authority loss: Stop/revoke/destructor remain
no-post retirement. The fixed **45-case** native X11 sanitizer selector and
separate **2-case** implicit-destructor lane remain unchanged. Clipboard stays
disabled.

**Linux first-real-desktop R9 acceptance matrix:**

| Physical boundary | Status |
| --- | --- |
| Original accepted R1 client/connection | **NOT RUN** |
| Client NTLM Type 3 and authenticated original connection | **NOT RUN** |
| Fresh R2 View/Input proof and owner consent | **NOT RUN** |
| Native unlocked X11 `seat0` audit and original R5 owner | **NOT RUN** |
| R3 Share/GraphicsReady and mapped geometry | **NOT RUN** |
| First current-generation R5 XShm capture frame | **NOT RUN** |
| Complete R4/R3 DATA and original R1 accepted-byte receipts | **NOT RUN** |
| Actual independently received matching client FRAME_ACK | **NOT RUN** |
| Keyboard/mouse and RandR resize with held owner preserved | **NOT RUN** |
| Stop / terminal authority retirement with zero cleanup posts | **NOT RUN** |
| Fresh reconnect with new client/native/capture generations | **NOT RUN** |

First-frame handoff remains single-owner: R10 composes the original accepted R1
lifetime with fresh R2 authorization, bounded R5 event drain/current RandR
observation, R4 credit preflight and synchronous XShm borrow. The borrow ends
before R3/R1 publication; R4 owns frame layout/credit/ACK membership, and
visibility requires complete original R1 receipts plus a separately consumed
real client FRAME_ACK. RandR retains the admitted XTEST owner/held bookkeeping
while replacing geometry-bound capture resources; terminal authority loss
clears bookkeeping without unauthorized releases.

Connector source/ownership/registry review **PASS**. Canonical local
`~/rdp-server/build/` configure/build/focused/full Debug+Release CTest, Xvfb,
ASan/UBSan and benchmark are **NOT RUN** in this connector environment.
Exact-publication-SHA hosted CI is **PENDING**. No physical X11 capture/input or
Clipboard operation was performed.

