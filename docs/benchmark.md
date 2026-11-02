## R8 malformed late Temporary Directory retirement is test-only (2026-11-02)

This increment adds one ordinary production-backed protocol regression and documentation only. Production CLIPRDR parsing, allocations, queues, TLS I/O, R2 permission checks, R3 receipt ownership, R10 scheduling and native X11 callbacks are unchanged. The test composes an existing bounded 520-byte parser failure with an existing positive-partial response receipt, so no throughput or latency benchmark is applicable. Benchmark NOT RUN; physical Clipboard/paste performance remains outside the disabled live-activation gate.

## R4 Linux dual-scheduler ACK pre-borrow source regression is test-only (2026-11-02)

The existing offline source-contract CTest adds a second read-only check for Linux `LinuxRuntimeHostControl` preflight/deferred-return ordering and negative mutations. It changes no native X11 capture, ClearCodec or x264 hot loop, reservation, 64-frame ACK window, R3 segmented DATA accounting, R1 TLS writer, memory layout or traffic. No physical frame, latency, throughput or FPS benchmark was run or is implied. Exact-SHA hosted correctness CTest and sanitizer checks, not synthetic performance claims, are the qualification gate.

## R3 buffered late Font List / partial Granted Control is correctness-only (2026-11-02)

This is a single new ordinary offline R1/R2/R3 production-linked regression. It changes no production protocol algorithm, allocation, reader, writer, frame encoder or scheduler. Zero/partial/full TLS receipt order, bounded client TPKT intake and Graphics surface mapping are correctness/ownership checks, not measured throughput or client-visible pixels. Benchmark NOT RUN; physical first-pixel latency and accepted client ACK remain separate authorization/evidence gates.

## R5 typed XShm arena denial is lifecycle correctness-only (2026-11-02)

One ordinary production-linked Xvfb regression exercises the already-bounded full-frame capture failure and existing XCB/XTEST teardown path. No production hot-path allocation, copy, capture schedule, encoder, TLS writer or ACK window changes. This is not a throughput, latency, FPS, first-visible-pixel or physical-input benchmark; **benchmark NOT RUN**. Future performance/visibility claims still require original owner-admitted native frames, exact R1 accepted-byte receipts and independently received genuine client FRAME_ACK plus client visibility evidence.

## R2 first-publication race regression is correctness-only (2026-11-02)

The new Windows fixture adds only a null-by-default internal test hook around the existing cold preference publication boundary and one offline CTest. Production still executes the same non-replacing `MoveFileExW(MOVEFILE_WRITE_THROUGH)` operation with no additional allocation, retry, protocol/frame/input/Clipboard work or scheduler state. No throughput benchmark is applicable or claimed; benchmark NOT RUN.

## R3 partial Share-write interleave is correctness-only (2026-11-02)

The new regression changes no production implementation, queue, allocation, parser, TLS I/O loop, licensing state machine or graphics scheduler. It drives an existing setup/Share interleave through original R1/R2/R3 owners only. No throughput benchmark is applicable or claimed; benchmark **NOT RUN** and hosted Debug/Release CTest is the executable gate.

## R1 cross-generation challenge identity regression is correctness-only (2026-11-01)

The production Type-2 encoder, SSL reader/writer, generated certificate, per-peer challenge, poll schedule and timeouts are unchanged. Only an offline real-loopback regression adds client-side leaf-fingerprint comparison across Stop/recredential/reconfigure/reconnect. The 9,166-microsecond owner Type-2-to-FIN observation is diagnostic ordering, not a throughput benchmark or timeout-tuning target. Benchmark NOT RUN.

## R8 malformed late-Capabilities retirement is test-only (2026-11-02)

This increment adds one ordinary production-backed protocol regression and documentation only. It changes no production parser branch, allocation, queue, TLS writer, R2 permission check, R10 scheduler, X11 callback or file path, so no throughput or latency benchmark is warranted. Clipboard latency, native paste and INCR performance remain unmeasured until separately authorized live activation; no such access is performed here.

## R2 oversized preference record denial is correctness-only (2026-11-01)

The new regression exercises cold private-file size validation, safe-default reset and existing atomic recovery only. It changes no production code, allocation policy, protocol/frame/input/Clipboard hot path or scheduler. No throughput benchmark is applicable or claimed; benchmark NOT RUN. Preserve bounded fixed-v1 I/O even if a synthetic benchmark would favor a looser parser.

## R2 Windows replacement primitive is cold-path correctness (2026-11-01)

Switching an existing private preferences publication from `MoveFileExW` replacement to `ReplaceFileW` runs only on explicit non-secret preference save. It changes no RDP packet/frame/input/Clipboard loop, allocation strategy or scheduler hot path. No throughput benchmark is required; correctness is qualified by Windows Debug/Release CTest.

## R2 Windows private preferences reader sharing (2026-11-01)

Adding Windows delete sharing to a cold-path private file read changes no RDP hot loop, allocation, socket, native frame/input or Clipboard operation. No throughput benchmark run or needed for this correctness increment. Validate through Windows Debug/Release CTest.

## R10 Start-time session retirement is correctness-only (2026-11-01)

The correction adds one credential/session validation only to the cold explicit Start path and one existing consent revalidation on a native-desktop failure path. It changes no per-packet, frame, input, Clipboard or steady-state scheduler hot loop and allocates no new state. No benchmark is required for this security/lifecycle correction; benchmark NOT RUN.

## R6 paired-evidence fixture repair is not a benchmark (2026-11-01)

The correction changes only offline Python evidence fixtures and assertions. It does not change production TLS, NTLM/CredSSP, parsing, allocation, transport, scheduler, native admission or client-visible behavior, so no performance benchmark is required or claimed.

## R3 mixed-join / partial licensing Stop is correctness, not throughput (2026-11-01)

The new production-linked R1/R2/R3 offline regression changes no protocol hot path, TLS buffering, native capture, memory allocation, scheduler or algorithm. No benchmark was run and no throughput, timing, real-client or pixel-visibility claim is justified. Original authenticated Microsoft-client and owner-native evidence remain independent.

## R8 later Format List response retirement has no hot-path change (2026-11-01)

This change adds only an offline production-backed test and canonical documentation. No production allocation, queue, TLS writer, R8 owner, R2 permission or X11 callback changes; the fixed 107-case Clipboard sanitizer selector is preserved. No benchmark was run, and real Clipboard latency/paste/INCR require separate owner authorization.

## R7 offline GUI LAN activation is correctness-only (2026-11-01)

The missing-preference-callback `activated` refresh and offscreen fixture corrections do not add protocol/graphics/clipboard hot-path work, network I/O, native session activity or new storage. They require correctness/negative CTests, not a throughput benchmark. Benchmark NOT RUN; no performance or live-listener qualification is inferred.

## R10 owner-change endpoint regression is not a throughput result (2026-11-01)

The new first-Start denial test changes no runtime code, hot-path work, buffer, scheduler, TLS writer, codec or permission behavior. No benchmark was run or is warranted by this test-only increment; physical frame latency and throughput remain separately unverified.

## Windows preference hard-link denial is correctness, not throughput (2026-11-01)

The added `GetFileInformationByHandle` link-count check runs only on cold preference file validation and introduces no protocol, frame, input, Clipboard, listener or credential hot-path work. No benchmark is required for this security-correctness hardening and none was run.

## R4 partial segmented DATA-to-resize fence is correctness, not throughput (2026-11-01)

The additional offline regression changes no production hot path, ACK window, native borrow, encoder, transport writer or scheduler; no performance benchmark was run. At 64 outstanding ACKs preflight must deny native pixel borrow, encoding, reservation and TLS write. No client-visible pixels can be inferred from GraphicsReady, native readiness, prepared ClearCodec bytes, completed local R1 receipts or synthetic ACK fixtures. Original-authority real-client pixel and genuine FRAME_ACK evidence remains an independent physical gate.

## R7 CLI Username byte-bound parity is not a benchmark (2026-11-01)

Changing the cold startup parser's non-secret Username ceiling from 128 to the
existing R2 256-byte record ceiling adds no runtime hot-path work, allocation,
network I/O, frame/clipboard processing or authorization operation. No
performance result is claimed and no benchmark is required for this
correctness/interoperability fix.

## R1 pre-TLS byte-accounting nonblocking handshake fairness (2026-11-01)

This change is test-harness scheduling only. The bounded pause occurs only while a nonblocking loopback TLS handshake fixture has not finished; the production R1 transport hot path, handshake deadlines, allocations and accepted-byte accounting are unchanged. No benchmark is required and none was run. The previously observed ~0.06 s spin exhaustion is not a production latency metric.

## R8 pre-Monitor client initialization denial is correctness, not throughput (2026-11-01)

Rejecting client Capabilities, Temporary Directory and Format List until the original server Monitor Ready is fully delivered changes only protocol sequencing and fail-closed state ownership. It adds no allocation, copy, packet loop, TLS writer, native Clipboard access or benchmarkable data path. No performance result is claimed and no benchmark is required for this correction. Future Clipboard latency measurement still begins from valid client Format List arrival after protocol initialization and genuine native authorization.

## R5 in-flight held-input revocation is not a benchmark (2026-11-01)

The new Xvfb correctness test adds no native production hot-path work or
performance measurements. No CPU, frame-rate, bandwidth or client-visibility
claim follows from it. Genuine first-frame evidence still requires original
R5 capture, R4/R3 publication, complete original R1 accepted-byte receipts
and a separately received matching client FRAME_ACK.

## R4/R10 exact native-frame boundary benchmark status (2026-11-01)

This is a correctness/fencing increment, not a throughput change. Tightening the callback to the exact R7 tight-BGRA stride adds no new allocation, copy, queue, encoder or transport owner. The 64-outstanding-frame path remains a preflight fast refusal: when credit is unavailable R10 must not borrow native pixels, encode ClearCodec, reserve a frame or initiate a new TLS frame write.

No benchmark is required to claim this correction and none was run in the connector environment. Future first-frame performance evidence must still measure the original native observation/borrow through R4 preparation, R3 segmented accepted-byte receipts, sole R1 wire progress and a genuine client FRAME_ACK/visibility observation. GraphicsReady, native readiness, local preparation, a complete local TLS write or a synthetic ACK are not benchmark evidence for visible pixels.

## R4 delayed stale-writer abort is correctness, not throughput (2026-11-01)

A late aborted partial/unsent segmented frame tests lifecycle ownership and outstanding ACK membership, not native capture, CPU, FPS, bandwidth or real client presentation. Benchmark NOT RUN. Do not infer physical visibility or performance.

## macOS 25 ms / 1,590-byte graphics pacing finding is a progress bound, not a benchmark (2026-11-01)

R3's protocol-owned DVC frame record carries at most 1,590 application payload bytes. Servicing exactly one immediately-progressing record every 25 ms therefore imposes a source-derived ceiling of about 63,600 payload bytes/second before TLS and outer-protocol overhead; this is sufficient to identify a scheduler progress defect but is not a measured throughput benchmark. The bounded-burst correction must not be reported as a performance result until the normal reproducible native/client benchmark gate exists.

## R4 ACK retirement/backpressure evidence is correctness, not a performance result (2026-11-01)

The 64-outstanding-frame preflight is a correctness/backpressure boundary: when R4 reports no credit, R10 must perform no native frame borrow, ClearCodec encode/reservation or TLS frame write. Likewise, rejecting a delayed ACK consume after generation retirement is lifecycle correctness. The new `graphics.frame-ack-intake-session-retirement-before-consume` regression and existing credit/segmented-receipt tests do not measure encode cost, bandwidth, latency, FPS or ACK turnaround and must not be reported as benchmark evidence.

No benchmark was run for this change. A future performance claim still requires the standard real workload measurements from native observation/damage through encode, queue, wire and genuine client ACK/visibility; GraphicsReady, native readiness, local preparation, complete local TLS write or synthetic ACK are not visibility/performance proof.

## Pre-TLS readiness dwell is diagnostic attribution, not a benchmark (2026-10-29)

Accepted-to-TLS Read/Write dwell describes how long the existing R1 owner
required a readiness direction. Native-poll duration and
readiness-observed-to-service age are non-additive subsets. These values
localize one interoperability stall; they are not latency targets, scheduler
benchmarks or evidence for changing timeout/TLS policy.

## Post-Type-2 wire counters remain diagnostics, not benchmarks (2026-10-27)

Encrypted/plaintext byte counts, TSRequest counts, alert/FIN/reset facts and
Type-2-to-first-byte / Type-2-to-EOF timings diagnose interoperability. They
are not performance targets and cannot justify timeout or throughput tuning.

## CREDSSP credential-source elapsed time is diagnostic only (2026-10-27)

Per-row `elapsed-us` is a steady-clock duration from fresh test-context
construction to that row's terminal oracle boundary. It is not a latency
benchmark, timeout recommendation, client-performance comparison or
authorization signal. Do not derive percentile or retry policy from these
single synthetic observations.

## Pre-Type-3 diagnostic timings are not performance benchmarks (2026-10-27)

The fail-only Type-2 creation-to-delivery age, Type-2-to-peer-EOF age,
first-post-Type-2-client-TLS-byte age, connection-local pre-auth
elapsed-at-peer-EOF value, post-Type-2 plaintext-byte count and complete
TSRequest count are single-attempt lifecycle diagnostics. They distinguish
where one authentication exchange stopped; they are not latency SLAs,
throughput measurements, percentile samples or evidence that one client/TLS
version is faster than another. No production timeout, retry, authentication,
credential or identity decision may depend on them.

Do not publish p50/p95/p99, bandwidth or optimization claims from these
terminal values. A missing first-client-data observation is evidence that the
existing server receive path consumed no post-Type-2 TLS bytes before the
terminal boundary, not a network-performance measurement. Any future
performance comparison must use the benchmark methodology below, fixed
workloads and repeated samples; real-client benchmarking remains a separately
authorized activity.

# Benchmark standards — reliable native RDP-server measurements

**Mandatory:** Read [AGENTS.md](../AGENTS.md), [VISION.md](VISION.md),
[testing_standards.md](testing_standards.md),
[compile.md](compile.md), and the living
[roadmap/TODO](ROADMAP.md) with every relevant prompt.
Record performance lessons in this single reference, not fragmented
benchmark reports.

## Goal

A fast native C++23 standards-compliant server with low CPU, RAM, latency,
bandwidth, allocation and queueing costs even on old dual-core and
scalar-only CPUs. Never sacrifice protocol semantics, security,
frame/clipboard correctness or authentication for a benchmark score.

## Reproducible methodology

Pin and report exact commit, compiler/config, client/version, server OS,
CPU/RAM/SIMD, negotiated codecs/capabilities, display dimensions,
network RTT/loss/bandwidth, fixture hashes, sample count, load and warmup.
Compare **identical verified workloads** on a controlled environment;
measure baseline variance and regressions. Separate parser microbenchmarks,
simulated peers and real authenticated client/desktop tests.

All generated fixtures, profiles, timing output and compiled benches
belong in the sole reused **`~/rdp-server/build/`** local root.
Benchmarks should be reusable, resource-bounded and opt-in rather than
long-running default CTests. Real desktops, screenshot contents,
clipboard captures or client credentials require explicit authorization.

## Measure meaningful boundaries

| Boundary | Metrics |
| --- | --- |
| Connect | X.224, TLS, CredSSP, MCS and activation phase timings |
| Graphics | Damage → encode → queue → wire → ACK/visibility; bytes/frame |
| Input | Event dispatch and client-observed responsiveness under load |
| Clipboard | Client offer → request → first/last byte → validated ready → OS selection response → consumer-visible paste, with X11 INCR and Firefox File receipt |
| Runtime | CPU, peak RSS, allocation counts/bytes, copies, queue depth |
| Reliability | reconnect/cancel/timeout cost and throughput at fixed RTT |

Report p50/p95/p99 (where sample count supports them), tail stalls,
throughput, resource cost and explicit noise/clock limitations.
Do not infer network bytes from call count, performance from parser
unit tests, or synchronous browser receipt from completed X11 transfer.
Keep scalar parity and negative regression tests green before accepting
an optimization.

## Clipboard latency and resource methodology (planned)

Measure from the **actual client Format List arrival**, not from an
unobservable screenshot taken while Windows App was backgrounded.
Separately record time from screenshot to announcement when the client
exposes it and label this *client focus/privacy delay*, not server latency.
Compare text, PNG, DIBV5/DIB fallback and file descriptors under the same
client and network conditions with and without bounded prefetch:

- Offer → Format Data Request, request → first/last response byte,
  response → validation/cache readiness, ready → local format conversion,
  OS paste request → completion, and consumer-visible paste. Track
  p50/p95/p99 and timeout/failure counts, not only payload throughput.
- Record compressed PNG and decoded image sizes, decompression CPU,
  conversion allocations, peak RSS, event-loop stalls, X11 INCR chunk
  progression, new-generation invalidation and clipboard-manager takeovers.
  Avoid unbounded prefetch or whole-file buffering.
- For copied files, record descriptor latency and FileContents stream-ID
  request/response timings, bounded buffer usage, destination integration
  cost and end-to-end successful paste for small/large files. Do not count
  network completion as success if the native file manager cannot open
  the advertised item.
- Measure macOS Windows App background/refocus and immediate paste before
  cached data is ready separately; Firefox success requires a synchronous
  non-null `image/png` `File`, not merely valid PNG bytes delivered to X11.

These are future benchmark contracts; no production clipboard latency
or browser-paste measurements have been taken.

## Honest baseline

The present native implementation is a **static protocol library**,
not an accepted real desktop server. Historical patched-xrdp numbers
are not native RDP-server results. Record first native measurements
only after end-to-end functionality; do not invent a throughput baseline.
Update this file and existing TODO in the same implementation commit.


## R4 graphics recovery repeatability and future end-to-end benchmark gate

Before an authorized R3 Graphics DVC sender exists, x264/BGRA CTest timings
are regression-repeatability diagnostics only. Native-BGRA ingress CTests add
layout, lifetime and generation correctness evidence but do **not** measure
capture throughput, frame rate, latency or a client-visible threshold. Reuse
the canonical checkout and build root:

```bash
cd ~/rdp-server
git switch main
git pull --ff-only origin main
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --config Release --parallel 2 --target \
  test_gfx_presentation_lifecycle test_gfx_avc420_segmented_frame \
  test_x264_avc420_encoder test_x264_avc420_segmented_frame_producer
ctest --test-dir build -C Release -N -L x264
ctest --test-dir build -C Release -L x264 --repeat until-fail:30 \
  --output-on-failure
ctest --test-dir build -C Release \
  -R '^graphics\.(frame-delivery-unsent-cancellation|frame-delivery-partial-send-remains-terminal|avc420-segmented-frame-unsent-cancellation|x264-segmented-unsent-cancel-idr|x264-bgra-unsent-cancel-idr|frame-ack-decode-progress(-observation)?)$' \
  --repeat until-fail:30 --output-on-failure
```

Record exact commit/compiler/CPU and per-run test timing only for gross
regression detection. Do not derive fps, queue thresholds, p95/p99 desktop
latency, bandwidth or client decode performance from these offline runs.

After genuine R2/R3 authorization, DRDYNVC, the Graphics DVC sender and one
native source are integrated, add an opt-in measurement driver under this
same `build/` root. Correlate monotonic timestamps for: native damage/event ->
capture ready -> BGRA/NV12 conversion -> x264 encode -> R4 segmented frame
ready -> first R3 outer-byte submit -> final R1 accepted byte ->
FRAME_ACKNOWLEDGE -> client-visible presentation when a client exposes that
signal. Record encoded bytes/frame, conversion/x264 CPU, allocations/RSS,
raw client queueDepth bytes and raw totalFramesDecoded.

Use fixed warmup/workload/network conditions and sufficient samples before
reporting p50/p95/p99. Preserve queueDepth zero/unavailable/suspended and the
raw uint32 decoded counter. Neither observation defines a frame-rate policy;
calibrate any throttle only from measured real-client data.