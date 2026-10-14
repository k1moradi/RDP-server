# Benchmark standards — reliable native RDP-server measurements

**Mandatory:** Read [AGENTS.md](AGENTS.md), [VISION.md](VISION.md),
[testing_standards.md](testing_standards.md),
[compile.md](compile.md), and the living
[roadmap/TODO](docs/ROADMAP.md) with every relevant prompt.
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
| Clipboard | Format List offer; request/first/last byte; X11 INCR; Firefox actual File receipt |
| Runtime | CPU, peak RSS, allocation counts/bytes, copies, queue depth |
| Reliability | reconnect/cancel/timeout cost and throughput at fixed RTT |

Report p50/p95/p99 (where sample count supports them), tail stalls,
throughput, resource cost and explicit noise/clock limitations.
Do not infer network bytes from call count, performance from parser
unit tests, or synchronous browser receipt from completed X11 transfer.
Keep scalar parity and negative regression tests green before accepting
an optimization.

## Honest baseline

The present native implementation is a **static protocol library**,
not an accepted real desktop server. Historical patched-xrdp numbers
are not native RDP-server results. Record first native measurements
only after end-to-end functionality; do not invent a throughput baseline.
Update this file and existing TODO in the same implementation commit.
