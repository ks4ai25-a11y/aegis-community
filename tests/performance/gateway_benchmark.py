#!/usr/bin/env python3
"""Reproducible gateway latency benchmark (v4 manual H5, A5 target: added p95 <= 15 ms at 100 RPS).

Compares, over the same Docker network path, requests sent straight to the synthetic demo origin
(baseline) with requests through the Aegis gateway in Observe and in Protect, for a ~1 KiB GET and a
10 KiB POST of benign data, at a fixed open-loop rate. Records p50/p95/p99, throughput, statuses,
gateway CPU/memory and telemetry loss. Only the bundled synthetic origin is contacted.

Environment: the multi_site_acceptance.py variables plus
  AEGIS_PROJECT      Compose project name (default aegis-community)
  AEGIS_BENCH_RPS    rate (default 100)   AEGIS_BENCH_SECONDS  measured seconds per case (default 30)
  AEGIS_BENCH_OUT    JSON evidence path
Build the generator first: (cd tests/performance/loadgen && CGO_ENABLED=0 GOOS=linux go build -o /tmp/aegis-loadgen .)
"""
import json, os, pathlib, platform, subprocess, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "integration"))
import multi_site_acceptance as m

PROJECT = os.environ.get("AEGIS_PROJECT", "aegis-community")
RPS = int(os.environ.get("AEGIS_BENCH_RPS", "100"))
SECONDS = int(os.environ.get("AEGIS_BENCH_SECONDS", "30"))
LOADGEN = os.environ.get("AEGIS_LOADGEN", "/tmp/aegis-loadgen")
IMAGE = "alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659"
QUERY = "/catalog?query=" + "benign" * 160  # ~1 KiB request line, no attack patterns


def loadgen(url, host="", body=0):
    cmd = ["docker", "run", "--rm", "--network", PROJECT + "_origin_net", "-v", LOADGEN + ":/loadgen:ro", "--cap-drop", "ALL", "--read-only", IMAGE,
           "/loadgen", "-url", url, "-rps", str(RPS), "-duration", f"{SECONDS}s", "-warmup", "5s", "-body", str(body)] + (["-host", host] if host else [])
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
    for name, body in [("get_1kib", 0), ("post_10kib", 10240)]:
        url = QUERY if body == 0 else "/catalog"
        cases.append({"case": name, "path": "baseline_origin_direct", **loadgen("http://demo-origin:8080" + url, body=body)})
        for mode in ["observe", "protect"]:
            set_mode(mode)
            cases.append({"case": name, "path": "gateway_" + mode, **loadgen("http://gateway:8080" + url, "demo.example.test", body)})
    loss1 = dropped()
finally:
    set_mode(original)

summary = {}
for name in ["get_1kib", "post_10kib"]:
    base = next(c for c in cases if c["case"] == name and c["path"] == "baseline_origin_direct")
    for c in cases:
        if c["case"] == name and c["path"] != "baseline_origin_direct":
            summary[name + "/" + c["path"]] = {"added_p50_ms": round(c["p50_ms"] - base["p50_ms"], 2), "added_p95_ms": round(c["p95_ms"] - base["p95_ms"], 2), "added_p99_ms": round(c["p99_ms"] - base["p99_ms"], 2),
                                               "p95_target_15ms_met": c["p95_ms"] - base["p95_ms"] <= 15, "non_2xx": sum(v for k, v in c["statuses"].items() if not k.startswith("2")), "errors": c["transport_errors"]}
evidence = {"schema_version": "1.0", "test_scope": "local-gateway-latency-synthetic", "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "host": {"platform": platform.platform(), "machine": platform.machine(), "docker_cpus": subprocess.run(["docker", "info", "--format", "{{.NCPU}}"], capture_output=True, text=True).stdout.strip(),
                     "docker_mem_bytes": subprocess.run(["docker", "info", "--format", "{{.MemTotal}}"], capture_output=True, text=True).stdout.strip()},
            "method": f"open-loop {RPS} RPS for {SECONDS}s after 5s warm-up, same Docker network for baseline and gateway, plain HTTP, CRS PL1 threshold 5, no AI or scanner jobs",
            "telemetry_loss": {"events_dropped_delta": loss1[0] - loss0[0], "ingest_rejected_delta": loss1[1] - loss0[1]},
            "summary": summary, "cases": cases,
            "limitations": ["Single run on a developer laptop under Docker Desktop; other workloads were running. Not the reference 4 vCPU Linux AMD64 system.", "No TLS, no sampling-error estimate across repeated runs.", "Synthetic origin with tiny responses; real applications will differ."]}
out = os.environ.get("AEGIS_BENCH_OUT")
if out:
    pathlib.Path(out).write_text(json.dumps(evidence, indent=1) + "\n")
print(json.dumps({"summary": summary, "telemetry_loss": evidence["telemetry_loss"]}, indent=1))
