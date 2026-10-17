#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Remediation guidance and validated patch drafts on the bundled synthetic `vulnerable` fixture.
Requires the local model overlay for the draft check (skipped otherwise). Nothing is written to the
repository. Uses multi_site_acceptance.py environment variables."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import json, os, pathlib, time
import multi_site_acceptance as m

evidence = {"schema_version": "1.0", "test_scope": "local-remediation-synthetic", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": []}
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "alpha/fixtures/scanners/vulnerable/query.py"


def check(name, detail=None):
    evidence["checks"].append({"id": name, "result": "PASS", "detail": detail})
    print(name + ": PASS", flush=True)


try:
    m.login()
    before = FIXTURE.read_bytes()
    repo = next((r for r in m.call("/repos")["items"] if r["asset_id"] == "vulnerable"), None) or m.call("/repos", {"app_id": "app_demo", "asset_id": "vulnerable", "acknowledge_read_only": True}, expected=201)
    f = {"repository_id": repo["repository_id"], "category": "static_pattern", "summary": "SQL built by string concatenation", "path": "query.py", "line": 3, "package_name": "", "installed_version": "", "advisories": [], "rule_ids": ["B608"]}
    g = m.call("/findings/remediation", {"finding": f, "draft_patch": False})
    assert "bound parameters" in g["remediation"]["steps"][0] and g["remediation"]["advisory_only"]
    assert g["excerpt"] and any("db.execute" in l for l in g["excerpt"]["lines"])
    check("static_guidance_and_confined_excerpt")
    for bad in ["../../../etc/passwd", ".env"]:
        r = m.call("/findings/remediation", {"finding": {**f, "path": bad}, "draft_patch": False}, expected=400 if ".." in bad else 200)
        if ".." not in bad:
            assert r["excerpt"] is None, bad
    check("excerpt_refuses_escapes_and_uninventoried_files")
    r = m.call("/findings/remediation", {"finding": {**f, "path": "fake-secret.txt", "line": 1}, "draft_patch": True}, timeout=60)
    assert r["excerpt"]["redacted"] and not any("ghp_" in l for l in r["excerpt"]["lines"]), r["excerpt"]
    assert "credential" in r["remediation"]["patch_draft_note"] and not r["remediation"].get("patch_draft")
    check("credential_lines_redacted_and_never_sent_to_model")
    s = m.call("/findings/remediation", {"finding": {**f, "category": "secret_candidate", "path": "fake-secret.txt", "line": 1}, "draft_patch": True})
    assert s["excerpt"] is None and "static code findings only" in s["remediation"]["patch_draft_note"] and "Revoke" in s["remediation"]["steps"][0]
    check("secret_findings_never_excerpted_or_drafted")
    ai = m.call("/ai/status")
    if ai["provider"] != "none":
        draft = None
        for attempt in range(3):
            t = time.time()
            r = m.call("/findings/remediation", {"finding": f, "draft_patch": True}, timeout=300)["remediation"]
            if r.get("patch_draft"):
                draft = r["patch_draft"]
                break
        assert draft, r.get("patch_draft_note")
        assert draft["unified_diff"].startswith("--- a/query.py\n+++ b/query.py\n@@ ") and draft["applies_to_file_digest"].startswith("sha256:")
        check("validated_patch_draft", {"model": draft["model"], "attempts": attempt + 1, "seconds": round(time.time() - t, 1), "diff": draft["unified_diff"]})
    assert FIXTURE.read_bytes() == before, "repository was modified"
    check("repository_never_modified")
    evidence["result"] = "PASS"
finally:
    evidence["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    evidence.setdefault("result", "FAIL")
    out = os.environ.get("AEGIS_REMEDIATION_EVIDENCE_OUT")
    if out:
        pathlib.Path(out).write_text(json.dumps(evidence, indent=1) + "\n")
