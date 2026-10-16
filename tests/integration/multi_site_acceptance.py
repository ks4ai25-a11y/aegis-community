#!/usr/bin/env python3
"""Register a second site behind the local demo gateway and check isolation, attribution and
Observe-before-Protect. Uses only the bundled synthetic origin under a reserved .test host name.

Environment (defaults match deploy/compose.demo.yaml):
  AEGIS_CONSOLE_URL   http://127.0.0.1:7410
  AEGIS_GATEWAY_URL   http://127.0.0.1:8080
  AEGIS_COMPOSE_FILES colon-separated compose files (for reading the bootstrap token)
  AEGIS_CREDENTIAL    private file holding the demo owner passphrase
"""
import http.cookiejar, json, os, pathlib, secrets, subprocess, time, urllib.error, urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONSOLE = os.environ.get("AEGIS_CONSOLE_URL", "http://127.0.0.1:7410")
GATEWAY = os.environ.get("AEGIS_GATEWAY_URL", "http://127.0.0.1:8080")
FILES = os.environ.get("AEGIS_COMPOSE_FILES", str(ROOT / "deploy/compose.demo.yaml")).split(":")
CREDENTIAL = pathlib.Path(os.environ.get("AEGIS_CREDENTIAL", "/private/tmp/aegis-demo-test-credential"))
COMPOSE = ["docker", "compose"] + [x for f in FILES for x in ("-f", f)]
SITE = "site_shop"
HOST = "shop.example.test"
SQLI = "/test-pattern?query=1%27%20OR%20%271%27%3D%271"

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = ""
evidence = {"schema_version": "1.0", "test_scope": "local-multi-site-synthetic", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": []}


def call(path, body=None, headers=None, expected=200):
    h = {"Content-Type": "application/json", **(headers or {})}
    if body is not None and csrf:
        h["X-CSRF-Token"] = csrf
    req = urllib.request.Request(CONSOLE + "/api/v1" + path, data=None if body is None else json.dumps(body).encode(), headers=h)
    try:
        with opener.open(req, timeout=60) as r:
            code, raw = r.status, r.read(262144)
    except urllib.error.HTTPError as r:
        code, raw = r.code, r.read(262144)
    assert code == expected, (path, code, raw[:800])
    return json.loads(raw)


def check(name, detail=None):
    evidence["checks"].append({"id": name, "result": "PASS", "detail": detail})
    print(name + ": PASS", flush=True)


def gateway(path, host, expected, spoof="spoofed-id"):
    req = urllib.request.Request(GATEWAY + path, headers={"Host": host, "X-Aegis-Request-ID": spoof, "Cookie": "session=PRIVACY_CANARY_COOKIE_7731"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            code, h = r.status, r.headers
            r.read(8192)
    except urllib.error.HTTPError as r:
        code, h = r.code, r.headers
        r.read(8192)
    assert code == expected, (path, host, code, expected)
    return h


def login():
    global csrf
    if CREDENTIAL.exists():
        response = call("/auth/login", {"password": CREDENTIAL.read_text()})
    else:
        logs = subprocess.check_output(COMPOSE + ["logs", "--no-log-prefix", "controller"], cwd=ROOT, text=True)
        tokens = [json.loads(l)["token"] for l in logs.splitlines() if l.startswith("{") and "local_bootstrap_token" in l]
        assert tokens, "No bootstrap token; use a dedicated demo installation."
        password = secrets.token_urlsafe(24)
        response = call("/auth/bootstrap", {"token": tokens[-1], "password": password})
        fd = os.open(CREDENTIAL, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(password)
    csrf = response["csrf_token"]


def activate(candidate, reason):
    current = call("/sites/site_demo/policy")
    candidate = {**candidate, "parent_revision": current["digest"], "metadata": {"rationale": reason, "requested_by": "local-owner"}}
    preview = call("/sites/site_demo/policies/validate", candidate)
    assert preview["fixture_result"] == "PASS", preview["fixture_result"]
    call("/sites/site_demo/policies", candidate, expected=201)
    call("/sites/site_demo/policies/" + preview["candidate_digest"] + "/activate", {"reason": reason, "acknowledge_disruption_risk": True}, {"If-Match": '"' + current["digest"] + '"', "Idempotency-Key": secrets.token_hex(12)})
    return preview["candidate_digest"]


def events_for(site, request_id, deadline=20):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        page = call("/sites/" + site + "/events?limit=100&cursor=" + str(start_cursor))
        found = [x["event"] for x in page["items"] if x["event"]["request_id"] == request_id]
        if any(e["source"] == "caddy-access" for e in found) and any("942100" in e["rule_ids"] for e in found):
            return found
        time.sleep(0.25)
    raise AssertionError("no attributed events for " + request_id)


site = {"site_id": SITE, "display_name": "Synthetic shop", "hostnames": [HOST], "origin": "demo-origin:8080", "requested_mode": "observe", "crs": {"blocking_paranoia": 1, "executing_paranoia": 1, "inbound_anomaly_threshold": 5}, "exclusions": []}
def main():
    global start_cursor
    try:
        login()
        check("owner_session")
        base = call("/sites/site_demo/policy")["policy"]
        assert base["requested_mode"] == "observe" and not base.get("sites"), "Start from the initial Observe policy without sites"
        gateway("/catalog", HOST, 421)
        check("unregistered_host_refused_421")

        start_cursor = 0
        for _ in range(501):
            page = call("/sites/site_demo/events?limit=100&cursor=" + str(start_cursor))
            start_cursor = page["cursor"]
            if len(page["items"]) < 100:
                break

        bad = {**base, "schema_version": "1.1", "sites": [{**site, "origin": "169.254.169.254:80"}]}
        current = call("/sites/site_demo/policy")
        call("/sites/site_demo/policies/validate", {**bad, "parent_revision": current["digest"], "metadata": {"rationale": "metadata origin", "requested_by": "local-owner"}}, expected=400)
        check("metadata_origin_refused")
        early = {**base, "schema_version": "1.1", "sites": [{**site, "requested_mode": "protect"}]}
        call("/sites/site_demo/policies/validate", {**early, "parent_revision": current["digest"], "metadata": {"rationale": "protect before observe", "requested_by": "local-owner"}}, expected=400)
        check("protect_before_observation_refused")

        registered = activate({**base, "schema_version": "1.1", "sites": [site]}, "Register synthetic shop in Observe")
        listed = {s["site_id"]: s for s in call("/sites")["items"]}
        assert listed[SITE]["mode"] == "observe" and listed[SITE]["synthetic"] is False
        check("site_registered_in_observe", {"revision": registered})

        h = gateway(SQLI, HOST, 200, spoof="site_demo.0f2d3c4b-1a2b-4c3d-8e9f-001122334455")
        rid = h["X-Aegis-Request-ID"]
        assert rid.startswith(SITE + ".") and h["X-Aegis-Mode"] == "observe", rid
        check("gateway_assigned_site_request_id", {"spoofed_header_ignored": True})
        found = events_for(SITE, rid)
        assert all(e["site_id"] == SITE and e["synthetic"] is False for e in found)
        demo_page = call("/sites/site_demo/events?limit=100&cursor=" + str(start_cursor))
        assert not any(x["event"]["request_id"] == rid for x in demo_page["items"])
        check("events_attributed_only_to_site", {"records": len(found)})
        raw = json.dumps(found)
        assert "PRIVACY_CANARY_COOKIE_7731" not in raw and "OR" not in raw
        check("site_privacy_sanitized")
        incidents = call("/sites/" + SITE + "/incidents")["items"]
        assert any("942100" in i["summary"] and i["synthetic"] is False for i in incidents), incidents
        check("site_incident_attributed")
        endpoints = call("/sites/" + SITE + "/endpoints")["items"]
        assert any(e["route_template"] == "/test-pattern" for e in endpoints), endpoints
        check("site_endpoint_inventory")

        protected = activate({**base, "schema_version": "1.1", "sites": [{**site, "requested_mode": "protect"}]}, "Protect observed synthetic shop")
        h = gateway(SQLI, HOST, 403)
        assert h["X-Aegis-Request-ID"].startswith(SITE + ".") and h["X-Aegis-Mode"] == "protect"
        demo = gateway(SQLI, "demo.example.test", 200)
        assert demo["X-Aegis-Mode"] == "observe" and "." not in demo["X-Aegis-Request-ID"]
        check("protect_isolated_to_site", {"revision": protected})
        gateway("/catalog?query=benign", HOST, 200)
        check("site_benign_request_allowed")

        restored = activate({**base, "schema_version": "1.1"}, "Remove synthetic shop after acceptance")
        gateway("/catalog", HOST, 421)
        assert [s["site_id"] for s in call("/sites")["items"]] == ["site_demo"]
        check("site_removed_restores_421", {"revision": restored})
        evidence["result"] = "PASS"
    finally:
        evidence["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        evidence.setdefault("result", "FAIL")
        out = os.environ.get("AEGIS_EVIDENCE_OUT")
        if out:
            pathlib.Path(out).write_text(json.dumps(evidence, indent=1) + "\n")


if __name__ == "__main__":
    main()
