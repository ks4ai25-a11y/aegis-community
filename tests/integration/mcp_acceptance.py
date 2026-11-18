#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Pair the real bin/aegis-mcp bridge with a connector credential and drive it over stdio the way a
desktop AI app would. Checks read-only tools, the untrusted-data notice, refusal of writes and
revocation. Build the bridge first with `make mcp-build`. Uses multi_site_acceptance.py variables."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import json, os, pathlib, subprocess, tempfile, time, urllib.parse
import multi_site_acceptance as m

ROOT = pathlib.Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "bin/aegis-mcp"
evidence = {"schema_version": "1.0", **m.source_stamp(), "test_scope": "local-mcp-bridge", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": []}


def check(name, detail=None):
    evidence["checks"].append({"id": name, "result": "PASS", "detail": detail})
    print(name + ": PASS", flush=True)


def bridge(token_file, requests):
    # Each subprocess is its own stdio session.
    prefix = []
    if not requests or requests[0]["method"] != "initialize":
        prefix = [
            {"jsonrpc": "2.0", "id": "handshake", "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "acceptance", "version": "1"},
            }},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        ]
    p = subprocess.run([str(BRIDGE)], input="\n".join(json.dumps(r) for r in prefix + requests) + "\n", capture_output=True, text=True, timeout=60,
                       env={"PATH": os.environ.get("PATH", ""), "AEGIS_URL": m.CONSOLE, "AEGIS_CONNECTOR_TOKEN_FILE": token_file})
    assert p.returncode == 0, "bridge process failed"
    responses = [json.loads(l) for l in p.stdout.splitlines()]
    if prefix:
        assert responses and responses[0]["id"] == "handshake"
        assert responses[0]["result"]["protocolVersion"] == "2025-06-18"
        return responses[1:]
    return responses


def text(resp):
    return resp["result"]["content"][0]["text"]


try:
    m.login()
    issued = m.call("/connectors", {"name": "Acceptance MCP", "lifetime_hours": 2}, expected=201)
    assert issued["token_shown_once"] and issued["connector"]["scope"] == "read_defence_v1"
    listed = m.call("/connectors")["items"]
    assert all("token" not in c for c in listed), "token returned by list"
    check("connector_issued_token_shown_once")
    with tempfile.TemporaryDirectory() as d:
        token = os.path.join(d, "token")
        fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, issued["token"].encode())
        os.close(fd)
        incidents = m.call("/sites/site_demo/incidents?limit=5")["items"]
        inc = incidents[0]["incident_id"] if incidents else "missing"
        out = bridge(token, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "acceptance", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "aegis_list_sites", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "aegis_get_incident", "arguments": {"incident_id": inc}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "aegis_get_incident", "arguments": {"incident_id": "../../connectors"}}},
        ])
        assert [o["id"] for o in out] == [1, 2, 3, 4, 5], out
        tools = out[1]["result"]["tools"]
        assert tools and [t["name"] for t in tools if not t["annotations"]["readOnlyHint"]] == ["aegis_submit_draft_analysis"]
        check("bridge_initializes_with_one_draft_submission_tool", {"tools": [t["name"] for t in tools]})
        assert text(out[2]).startswith("UNTRUSTED DATA FROM AEGIS") and "site_demo" in text(out[2])
        check("bridge_reads_sites_with_untrusted_notice")
        if incidents:
            assert not out[3]["result"].get("isError") and inc in text(out[3])
            check("bridge_reads_incident_evidence")
        assert out[4]["result"]["isError"], "path-like identifier accepted"
        check("bridge_refuses_path_identifiers")
        if incidents:
            preview = m.call("/desktop/handoff-preview?incident_id=" + urllib.parse.quote(inc,safe=""))
            scoped = m.call("/desktop/handoffs", {
                "incident_id": inc,
                "connector_id": issued["connector"]["connector_id"],
                "preview_digest": preview["preview_digest"],
                "approve_redacted_export": True,
                "allow_analysis_draft": True,
            }, expected=201)
            request = {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
                "name": "aegis_get_handoff", "arguments": {"handoff_id": scoped["handoff_id"]},
            }}
            first, replay = bridge(token, [request, {**request, "id": 7}])
            assert not first["result"].get("isError")
            assert json.loads(text(first).split("\n\n", 1)[1]) == preview["bundle"]
            assert replay["result"]["isError"] and "404" in text(replay)
            check("bridge_delivers_exact_approved_handoff_once")
            observations = preview["bundle"]["observations"]
            if observations:
                draft = {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
                    "name": "aegis_submit_draft_analysis", "arguments": {
                        "idempotency_key": "fixture-handoff-draft-001",
                        "incident_id": inc, "handoff_id": scoped["handoff_id"],
                        "client_label": "Synthetic acceptance",
                        "claims": [{"claim": "The bundle contains a retained observation.", "kind": "observation",
                                    "source_ids": [observations[0]["evidence_id"]]}],
                        "limitations": ["This report covers the bundled fixture only."],
                        "proposed_steps": [],
                    },
                }}
                response, retried = bridge(token, [draft, {**draft, "id": 10}])
                assert not response["result"].get("isError") and not retried["result"].get("isError")
                receipt = json.loads(text(response).split("\n\n", 1)[1])
                assert receipt["state"] == "unverified"
                assert json.loads(text(retried).split("\n\n", 1)[1]) == receipt
                assert any(d["draft_id"] == receipt["draft_id"] for d in m.call(
                    "/desktop/drafts?incident_id=" + urllib.parse.quote(inc,safe=""))["items"])
                check("bridge_returns_evidence_bound_unverified_draft_idempotently")

        # The same credential cannot reach mutating or sensitive routes directly.
        for method, path in [("POST", "/sites/site_demo/policies/validate"), ("GET", "/audit"), ("GET", "/connectors"), ("POST", "/connectors")]:
            req = m.urllib.request.Request(m.CONSOLE + "/api/v1" + path, method=method, data=b"{}" if method == "POST" else None, headers={"Authorization": "Bearer " + issued["token"], "Content-Type": "application/json"})
            try:
                m.urllib.request.urlopen(req, timeout=10)
                raise AssertionError("connector reached " + path)
            except m.urllib.error.HTTPError as e:
                assert e.code == 403, (path, e.code)
        check("connector_refused_on_writes_and_sensitive_reads")
        m.call("/connectors/" + issued["connector"]["connector_id"] + "/revoke", {})
        after = bridge(token, [{"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "aegis_list_sites", "arguments": {}}}])
        assert after[0]["result"]["isError"] and "401" in text(after[0])
        check("revoked_connector_refused")
    audit = [x["record"].get("action") for x in m.call("/audit")["items"]]
    assert "connector.issued" in audit and "connector.revoked" in audit
    check("connector_lifecycle_audited")
    evidence["result"] = "PASS"
finally:
    evidence["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    evidence.setdefault("result", "FAIL")
    out = os.environ.get("AEGIS_MCP_EVIDENCE_OUT")
    if out:
        pathlib.Path(out).write_text(json.dumps(evidence, indent=1) + "\n")
