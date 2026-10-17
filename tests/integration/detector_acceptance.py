#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Drive bounded synthetic traffic at the local demo gateway and check that the deterministic
detectors record reproducible incidents from pseudonymous evidence. Uses the same environment
variables as multi_site_acceptance.py; never contacts anything but the local gateway/console."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import json, os, pathlib, secrets, time, urllib.error, urllib.request
import multi_site_acceptance as m

evidence = {"schema_version": "1.0", "test_scope": "local-detector-synthetic", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": []}


def check(name, detail=None):
    evidence["checks"].append({"id": name, "result": "PASS", "detail": detail})
    print(name + ": PASS", flush=True)


def hit(path):
    req = urllib.request.Request(m.GATEWAY + path, headers={"Host": "demo.example.test"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read(4096)
            return r.status
    except urllib.error.HTTPError as r:
        r.read(4096)
        return r.code


def wait_incident(detector, deadline=20):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        items = m.call("/sites/site_demo/incidents?limit=100")["items"]
        found = [i for i in items if i.get("detector_id") == detector]
        if found:
            return found[0]
        time.sleep(0.5)
    raise AssertionError("no " + detector + " incident")


try:
    m.login()
    run = secrets.token_hex(4)
    # DET-02: 40 distinct unknown paths from this client inside one minute.
    statuses = [hit("/probe-" + run + "-" + str(i)) for i in range(40)]
    assert statuses.count(404) >= 30, statuses
    incident = wait_incident("DET-02")
    detail = m.call("/incidents/" + incident["incident_id"])
    d = detail["detector"]
    assert d["detector_id"] == "DET-02" and d["threshold"] == 30 and d["observed"] >= 30 and d["response"] == "record_only", d
    assert detail["evidence"] and all(e.get("client_key") and e.get("path_key") for e in detail["evidence"])
    raw = json.dumps(detail)
    assert "probe-" + run not in raw and "127.0.0.1" not in raw and "172." not in raw, "raw path or address stored"
    check("enumeration_incident_recorded", {"observed": d["observed"], "evidence": len(detail["evidence"])})
    check("enumeration_evidence_pseudonymous")
    status = m.call("/system/status")
    assert status["detector_version"] == "1.0" and "detector_state_evicted" in status
    check("detector_loss_counter_exposed", {"evicted": status["detector_state_evicted"]})
    evidence["result"] = "PASS"
finally:
    evidence["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    evidence.setdefault("result", "FAIL")
    out = os.environ.get("AEGIS_DETECTOR_EVIDENCE_OUT")
    if out:
        pathlib.Path(out).write_text(json.dumps(evidence, indent=1) + "\n")
