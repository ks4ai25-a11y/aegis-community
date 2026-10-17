#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Closed defensive loop on the local demo: a synthetic CRS match becomes an incident, is assessed
(deterministically and, if configured, by the local model), and yields mitigation proposals whose
candidate revisions are checked by the isolated fixture. Nothing is activated.
Uses the environment variables documented in multi_site_acceptance.py."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import json, os, pathlib, time
import multi_site_acceptance as m

evidence = {"schema_version": "1.0", **m.source_stamp(), "test_scope": "local-assessment-synthetic", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": []}


def check(name, detail=None):
    evidence["checks"].append({"id": name, "result": "PASS", "detail": detail})
    print(name + ": PASS", flush=True)


try:
    m.login()
    base = m.call("/sites/site_demo/policy")
    assert base["policy"]["requested_mode"] == "observe" and not base["policy"]["exclusions"], "start from initial Observe policy"
    rid = m.gateway(m.SQLI, "demo.example.test", 200)["X-Aegis-Request-ID"]
    end = time.monotonic() + 20
    incident = None
    while time.monotonic() < end and not incident:
        for i in m.call("/sites/site_demo/incidents?limit=100")["items"]:
            d = m.call("/incidents/" + i["incident_id"])
            if "942100" in i["summary"] and any(e["request_id"] == rid for e in d["evidence"]):
                incident = d
                break
        time.sleep(0.5)
    assert incident, "no incident for synthetic match"
    waf = [e for e in incident["evidence"] if e["source"] == "coraza"]
    assert any(e.get("target") == "ARGS:query" for e in waf), waf
    assert "OR" not in json.dumps(incident), "matched value persisted"
    check("incident_records_argument_name_only", {"detector": incident["detector"]["detector_id"]})

    path = "/incidents/" + incident["incident_id"]
    a = m.call(path + "/assessment", {"use_model": False})
    assert a["provenance"]["assessor"] == "deterministic" and a["advisory_only"] and any("942100" in f for f in a["observed_facts"])
    check("deterministic_assessment", {"dossier_digest": a["provenance"]["dossier_digest"]})
    ai = m.call("/ai/status")
    if ai["provider"] != "none":
        t0 = time.monotonic()
        a = m.call(path + "/assessment", {"use_model": True}, timeout=240)
        assert a["advisory_only"] and a["provenance"]["dossier_digest"]
        refs = {e["event_id"] for e in incident["evidence"]}
        assert all(r in refs for h in a["hypotheses"] for r in h["evidence_refs"]), "model cited evidence outside the dossier"
        check("local_model_assessment", {"assessor": a["provenance"]["assessor"], "model": a["provenance"].get("model"), "fallback": a["provenance"].get("fallback_reason", ""), "seconds": round(time.monotonic() - t0, 1), "hypotheses": len(a["hypotheses"])})
    audit = m.call("/audit")["items"]
    assert any(x["record"].get("action") == "incident.assessed" for x in audit), "assessment not audited"
    check("assessment_audited")

    proposals = m.call(path + "/proposals")
    kinds = {p["kind"]: p for p in proposals["proposals"]}
    assert set(kinds) == {"exclusion", "protect"}, proposals
    x = kinds["exclusion"]["candidate_policy"]["exclusions"]
    assert len(x) == 1 and x[0].pop("expires_at", "") > time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), x
    assert x == [{"rule_id": 942100, "method": "GET", "path": "/test-pattern", "parameter": "query"}], x
    check("proposals_generated", {"kinds": sorted(kinds)})
    # The exclusion would remove the bundled negative control, so the isolated fixture must refuse it.
    pe = m.call("/sites/site_demo/policies/validate", kinds["exclusion"]["candidate_policy"])
    assert pe["fixture_result"] != "PASS", pe["fixture_result"]
    check("unsafe_exclusion_rejected_by_fixture", {"fixture_result": pe["fixture_result"]})
    pp = m.call("/sites/site_demo/policies/validate", kinds["protect"]["candidate_policy"])
    assert pp["fixture_result"] == "PASS", pp["fixture_result"]
    check("protect_proposal_passes_fixture", {"candidate": pp["candidate_digest"]})
    assert m.call("/sites/site_demo/policy")["digest"] == base["digest"], "a proposal changed the active policy"
    check("proposals_never_activate_themselves")
    evidence["result"] = "PASS"
finally:
    evidence["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    evidence.setdefault("result", "FAIL")
    out = os.environ.get("AEGIS_ASSESSMENT_EVIDENCE_OUT")
    if out:
        pathlib.Path(out).write_text(json.dumps(evidence, indent=1) + "\n")
