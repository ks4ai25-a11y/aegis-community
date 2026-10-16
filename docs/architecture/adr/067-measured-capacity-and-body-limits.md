# ADR 067: Measured gateway capacity, saturation-safe policy changes and per-site body limits

Status: implemented; measured on a local stack.

## Problem

There was no performance evidence (manual H5, A5). The first benchmark run froze policy changes: under load the gateway's admin API slowed, the forward reload outran the controller's 20 s client timeout, and the rollback reused the expired context. Investigation showed WAF inspection cost grows linearly with the length of a single field, so large bodies are a cheap CPU-exhaustion vector.

## Decision

1. `tests/performance/loadgen` is an open-loop fixed-rate generator (no coordinated omission); `gateway_benchmark.py` sweeps short GET (25/50/100 RPS), ~1 KiB GET (25/50) and 10 KiB POST (25) through the demo origin directly, Observe and Protect, recording p50/p95/p99, statuses, gateway CPU/memory and telemetry loss, and flags saturation.
2. Rollback after a failed forward reload uses a fresh 55 s deadline; deployer operations allow 50 s, the controller client 55 s and activation 60 s. The deployer logs failed operations and the controller logs why changes froze.
3. Sites accept `max_body_kib` (1–1024), applied to Caddy `request_body max_size` and Coraza body, no-files and in-memory limits. Unset sites render exactly as before.

## Results

Short GET: added p95 2.5–4.1 ms up to 100 RPS. ~1 KiB GET: 8.5–9.3 ms at 25–50 RPS. 10 KiB single-field POST at 25 RPS saturates two CPUs (p95 1.3 s in Protect). Single-request cost: 1 KiB 23 ms, 100 KiB 0.77 s, 500 KiB 3.6 s; realistic 10 KB JSON 7.8 ms. With a 16 KiB limit a 100 KiB body is refused with 413 in 0.17 s. See `docs/operators/performance.md` and `docs/evidence/gateway-benchmark.json`.

## Consequences

Default body handling is unchanged for compatibility; operators of API sites should set a limit. The numbers come from one laptop run and are not a claim about the reference server.
