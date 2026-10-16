#!/usr/bin/env python3
"""Reproducible gateway latency benchmark (v4 manual H5, A5 target: added p95 <= 15 ms at 100 RPS).

Compares, over the same Docker network path, requests sent straight to the synthetic demo origin
(baseline) with requests through the Aegis gateway in Observe and in Protect, for a ~1 KiB GET and a
10 KiB POST of benign data, at a fixed open-loop rate. Records p50/p95/p99, throughput, statuses,
gateway CPU/memory and telemetry loss. Only the bundled synthetic origin is contacted.

Environment: the multi_site_acceptance.py variables plus
  AEGIS_PROJECT      Compose project name (default aegis-community)
  AEGIS_BENCH_SECONDS  measured seconds per case (default 30)
  AEGIS_BENCH_OUT    JSON evidence path
Build the generator first: (cd tests/performance/loadgen && CGO_ENABLED=0 GOOS=linux go build -o /tmp/aegis-loadgen .)
"""
import json, os, pathlib, platform, subprocess, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "integration"))
import multi_site_acceptance as m

PROJECT = os.environ.get("AEGIS_PROJECT", "aegis-community")
SECONDS = int(os.environ.get("AEGIS_BENCH_SECONDS", "30"))
LOADGEN = os.environ.get("AEGIS_LOADGEN", "/tmp/aegis-loadgen")
IMAGE = "alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659"
QUERY = "/catalog?query=" + "benign" * 160  # ~1 KiB request line, no attack patterns


SCENARIOS = [("get_short", "/catalog?query=ordinary", 0, [25, 50, 100]), ("get_1kib", QUERY, 0, [25, 50]), ("post_10kib", "/catalog", 10240, [25])]


def loadgen(url, rps, host="", body=0):
    cmd = ["docker", "run", "--rm", "--network", PROJECT + "_origin_net", "-v", LOADGEN + ":/loadgen:ro", "--cap-drop", "ALL", "--read-only", IMAGE,
           "/loadgen", "-url", url, "-rps", str(rps), "-duration", f"{SECONDS}s", "-warmup", "5s", "-body", str(body)] + (["-host", host] if host else [])
    sampler = subprocess.Popen(["sh", "-c", f"sleep {SECONDS // 2 + 5}; docker stats --no-stream --format '{{{{.CPUPerc}}}} {{{{.MemUsage}}}}' {PROJECT}-gateway-1"], stdout=subprocess.PIPE, text=True)
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=SECONDS + 120)
    stats = sampler.communicate(timeout=60)[0].strip()
    if out.returncode != 0:
        raise RuntimeError(out.stderr)
    r = json.loads(out.stdout)
    r["gateway_cpu_mem_sample"] = stats
    return r


def set_mode(mode):
    p = m.call("/sites/site_demo/policy")
    if p["policy"]["requested_mode"] != mode:
        m.activate({**p["policy"], "requested_mode": mode}, "Benchmark " + mode)
    time.sleep(3)


def dropped():
    s = m.call("/system/status")
    return int(s["events_dropped_total"]), int(s["ingest_rejected_total"])


m.login()
original = m.call("/sites/site_demo/policy")["policy"]["requested_mode"]
cases = []
try:
    loss0 = dropped()
    for path in ["baseline_origin_direct", "gateway_observe", "gateway_protect"]:
        if path != "baseline_origin_direct":
            set_mode(path.split("_")[1])
        for name, url, body, rates in SCENARIOS:
            for rps in rates:
                base = "http://demo-origin:8080" if path == "baseline_origin_direct" else "http://gateway:8080"
                cases.append({"case": name, "path": path, **loadgen(base + url, rps, "" if path == "baseline_origin_direct" else "demo.example.test", body)})
                time.sleep(5)  # let the gateway drain before the next case
    loss1 = dropped()
finally:
    set_mode(original)

summary = {}
for c in cases:
    if c["path"] == "baseline_origin_direct":
        continue
    base = next(b for b in cases if b["path"] == "baseline_origin_direct" and b["case"] == c["case"] and b["target_rps"] == c["target_rps"])
    errors = c["transport_errors"] + sum(v for k, v in c["statuses"].items() if k.startswith("5"))
    summary[f'{c["case"]}@{c["target_rps"]}rps/{c["path"]}'] = {"p50_ms": round(c["p50_ms"], 2), "p95_ms": round(c["p95_ms"], 2), "p99_ms": round(c["p99_ms"], 2),
        "added_p95_ms": round(c["p95_ms"] - base["p95_ms"], 2), "p95_target_15ms_met": c["p95_ms"] - base["p95_ms"] <= 15 and errors == 0,
        "saturated": errors > 0 or c["achieved_rps"] < 0.95 * c["target_rps"] or c["p95_ms"] > 1000, "errors_or_5xx": errors, "gateway_cpu_mem": c["gateway_cpu_mem_sample"]}
evidence = {"schema_version": "1.0", "test_scope": "local-gateway-latency-synthetic", "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "host": {"platform": platform.platform(), "machine": platform.machine(), "docker_cpus": subprocess.run(["docker", "info", "--format", "{{.NCPU}}"], capture_output=True, text=True).stdout.strip(),
                     "docker_mem_bytes": subprocess.run(["docker", "info", "--format", "{{.MemTotal}}"], capture_output=True, text=True).stdout.strip()},
            "method": f"open-loop fixed-rate cases for {SECONDS}s after 5s warm-up, same Docker network for baseline and gateway, plain HTTP, CRS PL1 threshold 5, gateway limited to 2 CPUs and 768 MiB by the reference Compose file, no AI or scanner jobs",
            "telemetry_loss": {"events_dropped_delta": loss1[0] - loss0[0], "ingest_rejected_delta": loss1[1] - loss0[1]},
            "summary": summary, "cases": cases,
            "limitations": ["Single run on a developer laptop under Docker Desktop; other workloads were running. Not the reference 4 vCPU Linux AMD64 system.", "No TLS, no sampling-error estimate across repeated runs.", "Synthetic origin with tiny responses; real applications will differ."]}
out = os.environ.get("AEGIS_BENCH_OUT")
if out:
    pathlib.Path(out).write_text(json.dumps(evidence, indent=1) + "\n")
print(json.dumps({"summary": summary, "telemetry_loss": evidence["telemetry_loss"]}, indent=1))
