

## R1 owned-TLS licensing cancellation and stale-receipt fence (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** \`2e9b5775077a28593dc6d717c6daecbc3db3141c\`.

The newer R1 bounded-readiness fixture increment
\`0a376216a88733082926c49b3932f70d80af2133\` now has meaningful exact-SHA
hosted evidence in Actions run \`38975448171\`: Linux/GCC **503/503 Debug +
503/503 Release PASS**, macOS/AppleClang **426/426 Debug + 426/426 Release
PASS**, Windows/MSVC **456/456 Debug + 456/456 Release PASS**, and the bounded
R1/R3 Clang ASan/UBSan selection **77/77 PASS**. Both
\`transport.tcp-owned-tls-application-partial-write\` and
\`transport.tcp-owned-r3-connect-response-slice\` executed in every hosted
Debug/Release suite and as selected sanitizer tests. This supersedes the
earlier zero-job workflow as R1 validation evidence.

R1 now adds two production-backed cross-road cancellation regressions without
changing production transport or licensing code:
\`transport.tcp-owned-r3-license-request-cancel-replay\` and
\`transport.tcp-owned-r3-platform-challenge-cancel-replay\`. Both use the real
ephemeral loopback \`OwnedPreauthTcpConnection\`, OpenSSL TLS and the existing
R3 receipt gates. The License Request case proves cancellation before any write
and after a real positive forced-fragment TLS write: only the accepted prefix
advances the R3 suffix receipt, R1 becomes terminal, explicit R3 gate
retirement closes licensing without delivery, and both current and older
receipts are rejected. It does not claim already accepted TLS bytes were
retracted. The Platform Challenge case deterministically cancels before the
94-byte packet is written, proves R1 closure alone cannot mutate R3, then
explicitly retires the R3 gate and rejects stale completion/requeue.

The existing WANT path remains bounded and direction-exact: the License Request
case preserves the current span/receipt across zero-byte WANT and polls only
R1's recorded interest before retry. The already validated application-I/O,
License Request, Platform Challenge and cancellation tests provide the
complementary short-packet/WANT/read coverage; no scheduler sleep, hidden retry,
second TLS reader, transport-to-R3 coordinator or duplicate lifecycle is added.
The optional truncated-inbound fixture is not duplicated in this increment
because R1 exposes plaintext byte progress only and has no frame-forwarding
owner; incomplete-frame assembly remains the existing caller/R3 boundary.

R3's validated \`RdpLicensingAuthorityGrant\` snapshot and R10's administrator
licensing provisioning preflight remain offline/non-live authority boundaries.
They create no receipt-bound New/Upgrade publication, so they do not justify a
new R1 transport surface. R1's 18 KiB application-I/O ceiling and sole
socket/BIO/SSL ownership remain unchanged.

Canonical owner-local \`~/rdp-server/build/\` execution is **NOT RUN** in this
connector environment because the synchronized checkout is unavailable; no
alternate persistent build root, branch or patch artifact is created. Exact
publication-SHA hosted platform, sanitizer, documentation-policy and
SDK/package evidence for the two new cases is pending. M1 owner-platform
same-SHA evidence remains **NOT RUN** and M2/M3 remain **OPEN / NOT ACCEPTED**.


## R4 client decode-backlog observation exact-SHA hosted receipt (2026-10-16)

**Implementation:** `35833ba667a110ec859e04958d2a4ef269616012`.  
**Actions:** `38976220846` — **SUCCESS**.

The sole R4 presentation owner now exposes the already-owned
FRAME_ACKNOWLEDGE backlog facts without creating a throttle policy:
`expectingFrameAcknowledgements()`, `clientQueueDepthAvailable()` and
`clientQueueDepthBytes()`. Positive finite `queueDepth` values remain client
buffered-byte counts; zero remains explicitly unavailable, and suspension
clears the count and ACK expectation.

Dedicated production-backed
`graphics.frame-ack-backpressure-observation` passed in every normal hosted
configuration and under the portable R4 sanitizer gate:
- **Linux/GCC:** Debug **509/509 PASS**, Release **509/509 PASS**; new case
  **#270** in both.
- **macOS/Clang:** Debug **432/432 PASS**, Release **432/432 PASS**; new case
  **#255** in both.
- **Windows/MSVC:** focused native preflight **51/51 PASS** in Debug and
  Release; full Debug **462/462 PASS**, Release **462/462 PASS**; new case
  **#255** in both.
- **Clang ASan+UBSan portable R4 RDPGFX:** **34/34 PASS**; the new case is
  selected and passes as item **14/34**. Existing R4 x264/BGRA remains
  **20/20 PASS** and RDPGFX capability negotiation remains **4/4 PASS**.
- Documentation policy, independent R7 sanitizer, installed-SDK consumer,
  package/digest/upload and all remaining configured sanitizer/fuzzer groups
  PASS; untagged prerelease publication is correctly SKIPPED.

This closes the observation-boundary increment only. No frame-rate threshold,
timer, additional queue, second scheduler, DVC router or authorization path is
introduced. Canonical owner-local `~/rdp-server/build` validation and owner
Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 commands remain
**NOT RUN** in this connector environment. Genuine authenticated R3
`Microsoft::Windows::RDS::Graphics` DVC admission/full-send, native capture
performance and Microsoft-client visible graphics acceptance remain
**BLOCKED/NOT RUN**. Gate B and M3/M4/M5 remain **OPEN**.
