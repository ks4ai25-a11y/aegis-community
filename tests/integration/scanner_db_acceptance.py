#!/usr/bin/env python3
"""Offline OSV/Trivy database provisioning: fetch (operator, network) with bin/aegis-scanner-db,
verify, then run the pinned images with no network, read-only root, all capabilities dropped,
UID 10001 and the database mounted read-only, against the synthetic `vulnerable` and `safe`
fixtures. Also checks tampering is detected. Build first: (cd alpha && go build -o ../bin/aegis-scanner-db ./cmd/aegis-scanner-db).
Environment: AEGIS_SCANNER_DB_ROOT (scratch directory), AEGIS_SCANNER_DB_EVIDENCE_OUT."""
import json, os, pathlib, shutil, subprocess, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
# A fresh name each run: Docker Desktop's file sharing can keep a deleted directory
# cached, so a recreated directory with the same name may not be mountable at once.
DB = pathlib.Path(os.environ.get("AEGIS_SCANNER_DB_ROOT", "/tmp/aegis-scanner-db")) / time.strftime("run-%Y%m%dT%H%M%S")
CLI = str(ROOT / "bin/aegis-scanner-db")
LOCK = json.loads((ROOT / "tools/scanners.lock.json").read_text())
IMAGES = {t["id"]: t["image"] for t in LOCK["tools"]}
FIXTURES = ROOT / "alpha/fixtures/scanners"
HARDEN = ["--rm", "--pull=never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001",
          "--tmpfs", "/tmp:rw,noexec,nosuid,size=96m,uid=10001,gid=10001", "-e", "HOME=/tmp"]
evidence = {"schema_version": "1.0", "test_scope": "local-offline-scanner-databases", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": []}


def check(name, detail=None):
    evidence["checks"].append({"id": name, "result": "PASS", "detail": detail})
    print(name + ": PASS", flush=True)


def scan(tool, fixture):
    mount = {"osv_v2": ("osv", [], ["-e", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv"]), "trivy": ("trivy", ["--cache-dir", "/db/trivy"], [])}[tool]
    args = ["docker", "run", *HARDEN, *mount[2], "--mount", f"type=bind,src={DB / mount[0]},dst=/db/{mount[0]},readonly", "--mount", f"type=bind,src={FIXTURES / fixture},dst=/src,readonly", IMAGES[tool]]
    if tool == "osv_v2":
        args += ["scan", "source", "--offline-vulnerabilities", "--no-resolve", "--format", "json", "-r", "/src"]
    else:
        args += ["fs", "--scanners", "vuln", "--skip-db-update", "--skip-java-db-update", "--offline-scan", *mount[1], "--format", "json", "/src"]
    out = subprocess.run(args, capture_output=True, text=True, timeout=600)
    d = json.loads(out.stdout)
    if tool == "osv_v2":
        # Primary IDs only: newer advisories list older CVEs as aliases.
        return out.returncode, {v["id"] for r in d.get("results", []) for p in r.get("packages", []) for v in p.get("vulnerabilities", [])}
    return out.returncode, {v["VulnerabilityID"] for r in d.get("Results", []) for v in (r.get("Vulnerabilities") or [])}


try:
    t = time.time()
    subprocess.run([CLI, "fetch", str(DB), "--tools", "osv_v2,trivy", "--ecosystems", "npm,PyPI", "--lock", str(ROOT / "tools/scanners.lock.json")], check=True, timeout=3600)
    manifest = json.loads((DB / "manifest.json").read_text())
    assert {d["tool"] for d in manifest["databases"]} == {"osv_v2", "trivy"}
    check("operator_fetch_records_manifest", {"seconds": round(time.time() - t), "databases": [{"tool": d["tool"], "digest": d["digest"], "built_at": d["upstream_built_at"], "files": len(d["files"]), "bytes": sum(f["size"] for f in d["files"])} for d in manifest["databases"]]})
    v = json.loads(subprocess.run([CLI, "verify", str(DB), "--json"], capture_output=True, text=True, check=True).stdout)
    assert all(not s["stale"] for s in v["databases"]), v
    check("verify_rehashes_and_reports_fresh", v)
    results = {}
    for tool in ("osv_v2", "trivy"):
        for fx in ("vulnerable", "safe"):
            code, ids = scan(tool, fx)
            results[f"{tool}/{fx}"] = sorted(ids)
            assert code in (0, 1), (tool, fx, code)
    # lodash 4.17.20 (vulnerable) is affected by CVE-2021-23337 / GHSA-35jh-r3h4-6jhm, fixed in 4.17.21 (safe).
    assert "GHSA-35jh-r3h4-6jhm" in results["osv_v2/vulnerable"] and "CVE-2021-23337" in results["trivy/vulnerable"], results
    assert "GHSA-35jh-r3h4-6jhm" not in results["osv_v2/safe"] and "CVE-2021-23337" not in results["trivy/safe"], results
    check("hardened_offline_scans_find_known_advisory", results)
    target = next(p for p in (DB / "osv").rglob("all.zip"))
    with open(target, "ab") as f:
        f.write(b"x")
    assert subprocess.run([CLI, "verify", str(DB)], capture_output=True, text=True).returncode != 0
    check("tampered_database_refused")
    evidence["result"] = "PASS"
finally:
    evidence["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    evidence.setdefault("result", "FAIL")
    out = os.environ.get("AEGIS_SCANNER_DB_EVIDENCE_OUT")
    if out:
        pathlib.Path(out).write_text(json.dumps(evidence, indent=1) + "\n")
