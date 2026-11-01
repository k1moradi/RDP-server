## R9 P0 — preserve run identity in SHA-mismatch self-test (2026-11-01)

- Authoring parent `d331f8f7716cdb645acb34068dc703e254a69d40`. The prior R9 run-provenance hardening correctly requires a positive outer workflow `run.id`, matching job `run_id`, and matching artifact `workflow_run.id/head_sha`, but its own SHA-mismatch negative self-test still omitted `run.id`. The classifier therefore rejected the fixture as `INVALID_RUN` before reaching the intended `SHA_MISMATCH` assertion, causing both fast CI structure guards to fail.
- Keep the production classifier unchanged. Correct only that malformed negative fixture by retaining the same valid `run_id` while changing `head_sha`; this tests exactly the intended dimension and preserves the new cross-run denial coverage. R1 TLS/NTLM code, CTest inventory, sanitizer selectors, credentials, listeners and physical-client gates are unchanged.
- Source/self-test review PASS. Connector-local canonical build/full CTest/sanitizers/benchmarks are NOT RUN; publication-SHA hosted structure/full CI remains the next exact-SHA gate. Physical Windows App/mstsc evidence remains separately owner-gated.

