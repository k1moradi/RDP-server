## Pre-Type-3 diagnostic timings are not performance benchmarks (2026-10-27)

The fail-only Type-2 creation-to-delivery age and connection-local pre-auth
elapsed-at-peer-EOF values are single-attempt lifecycle diagnostics. They are
not latency SLAs, throughput measurements, percentile samples or evidence that
one client/TLS version is faster than another. No production timeout, retry,
authentication or identity decision may depend on them.

Do not publish p50/p95/p99 or optimization claims from these terminal values.
Any future performance comparison must use the benchmark methodology below,
fixed workloads and repeated samples; real-client benchmarking remains a
separately authorized activity.

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