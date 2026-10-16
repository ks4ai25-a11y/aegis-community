# Gateway performance and capacity

Measured with `tests/performance/gateway_benchmark.py` (open-loop fixed rate, same Docker network for baseline and gateway, plain HTTP, CRS paranoia 1, gateway limited to 2 CPUs and 768 MiB by the reference Compose file). Single run on an Apple-silicon laptop under Docker Desktop with other workloads present — not the reference Linux server. Evidence: `docs/evidence/gateway-benchmark.json`.

| Request | Rate | Added p95 (Observe / Protect) | Gateway CPU |
| --- | --- | --- | --- |
| short GET | 25–100 RPS | 2.5–4.1 ms | ≤ 20 % |
| ~1 KiB query GET | 25–50 RPS | 8.5–9.3 ms | ≤ 51 % |
| 10 KiB single-field POST | 25 RPS | 217 ms / 1,276 ms (saturated) | ~200 % |

The manual's target (added p95 ≤ 15 ms at 100 RPS for 1 KiB benign requests) is met for short requests and for ~1 KiB queries up to 50 RPS on this hardware; ~1 KiB queries cost about 18 ms of CPU each, so 100 RPS needs close to the full 2-CPU allowance. No telemetry was lost in the sweep.

## Large bodies are expensive

CRS inspects every argument with many regular expressions. For one long field the cost is roughly linear: about 7 ms of CPU per KiB (500 KiB ≈ 3.6 s). A realistic 10 KB JSON document with many short values costs about 8 ms. Because a few large requests per second can exhaust the gateway's CPU:

- set **Maximum request body (KiB)** on each site to the largest body it really accepts (for example 16–64 for JSON APIs); larger bodies are refused with 413 before inspection;
- add a per-client **rate limit**;
- give the gateway more CPUs (`cpus` in `deploy/compose.demo.yaml`) for high-volume sites.

Policy changes stay safe under load: if a reload is slow, the rollback runs with its own deadline, and a frozen controller re-checks the gateway every 30 seconds.
