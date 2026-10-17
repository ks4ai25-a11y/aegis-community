#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Offline advisory databases through the guarded scanner executor (ADR 068).

Runs `aegis-research scan-offline` for OSV-Scanner and Trivy against the synthetic
`vulnerable` and `safe` fixtures with AEGIS_SCANNER_DB_ROOT set to a verified
database, then once without it as a control, and once with a tampered copy.
Needs a fetched database (bin/aegis-scanner-db fetch) and `make research-build`.
Environment: AEGIS_SCANNER_DB_ROOT (required), AEGIS_SCANNER_DB_EVIDENCE_OUT."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import json, os, pathlib, subprocess, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
DB = pathlib.Path(os.environ["AEGIS_SCANNER_DB_ROOT"])
CLI = str(ROOT / "bin/aegis-research")
evidence = {"schema_version": "1.0", "test_scope": "scanner-executor-offline-databases", "source_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": []}


def check(name, detail=None):
    evidence["checks"].append({"id": name, "result": "PASS", "detail": detail})
    print(name + ": PASS", flush=True)


def scan(tool, fixture, db):
    env = {k: v for k, v in os.environ.items() if k != "AEGIS_SCANNER_DB_ROOT"}
    if db:
        env["AEGIS_SCANNER_DB_ROOT"] = str(db)
    p = subprocess.run([CLI, "scan-offline", tool, str(ROOT / "alpha/fixtures/scanners" / fixture), str(ROOT)], capture_output=True, text=True, env=env, timeout=900)
    if not p.stdout.strip():
        return p.returncode, None, p.stderr.strip()[-300:]
    return p.returncode, json.loads(p.stdout), ""


def advisories(r):
    return sorted({a for f in r["result"]["findings"] for a in f.get("advisories", [])})


try:
    v = json.loads(subprocess.run([str(ROOT / "bin/aegis-scanner-db"), "verify", str(DB), "--json"], capture_output=True, text=True, check=True).stdout)
    digests = {d["tool"]: d["digest"] for d in v["databases"]}
    results = {}
    for tool, advisory in (("osv_v2", "GHSA-35jh-r3h4-6jhm"), ("trivy", "CVE-2021-23337")):
        for fx in ("vulnerable", "safe"):
            code, r, err = scan(tool, fx, DB)
            assert r and r["status"] == "completed" and r["cleanup_state"] == "complete", (tool, fx, code, err, r and r["status"])
            d = r["advisory_database"]
            assert d["database_digest"] == digests[tool] and d["container_path"] == ("/db/osv" if tool == "osv_v2" else "/db/trivy") and not d["stale"], d
            assert r["invocation"]["network_profile"] == "none"
            results[f"{tool}/{fx}"] = {"status": r["status"], "advisories": advisories(r), "database_digest": d["database_digest"], "age_hours": d["age_hours"]}
        # lodash 4.17.20 has CVE-2021-23337, fixed in 4.17.21.
        assert advisory in results[f"{tool}/vulnerable"]["advisories"] and advisory not in results[f"{tool}/safe"]["advisories"], results
    check("guarded_executor_scans_with_verified_read_only_database", results)
    code, r, err = scan("osv_v2", "vulnerable", None)
    assert r is None or r["status"] == "tool_error" and "advisory_database" not in r, (code, r and r["status"])
    check("without_database_no_result_is_claimed", {"status": r["status"] if r else "refused", "exit": code})
    target = next((DB / "osv").rglob("all.zip"))
    size = target.stat().st_size
    try:
        with open(target, "ab") as f:
            f.write(b"x")
        code, r, err = scan("osv_v2", "vulnerable", DB)
        assert r is None and code != 0, (code, r and r["status"])
    finally:
        os.truncate(target, size)  # restore the exact original bytes
    subprocess.run([str(ROOT / "bin/aegis-scanner-db"), "verify", str(DB)], check=True, capture_output=True)
    check("tampered_database_refused_before_launch", {"exit": code, "error": err})
    evidence["result"] = "PASS"
finally:
    evidence["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    evidence.setdefault("result", "FAIL")
    out = os.environ.get("AEGIS_SCANNER_DB_EVIDENCE_OUT")
    if out:
        pathlib.Path(out).write_text(json.dumps(evidence, indent=1) + "\n")
