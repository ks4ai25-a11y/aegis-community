#!/usr/bin/env python3
"""Exercise only the local bundled demo. Never submits arbitrary targets or commands."""
import hashlib, http.cookiejar, json, os, pathlib, secrets, subprocess, time, urllib.request, urllib.error
from local_context import CREDENTIAL_FILE
ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy/compose.demo.yaml")]
jar = http.cookiejar.CookieJar()
http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = ""
evidence = {"schema_version":"1.0", "test_scope":"local-bundled-synthetic-demo", "started_at":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()), "checks":[]}
def call(path, body=None, headers=None, expected=200):
    h = {"Content-Type":"application/json", **(headers or {})}
    if body is not None and csrf: h["X-CSRF-Token"] = csrf
    req = urllib.request.Request("http://127.0.0.1:7410/api/v1"+path, data=None if body is None else json.dumps(body).encode(), headers=h)
    try:
        with http.open(req,timeout=55) as r: code,raw=r.status,r.read(131072)
    except urllib.error.HTTPError as r: code,raw=r.code,r.read(131072)
    assert code==expected, (path,code,raw[:1000])
    return json.loads(raw)
def check(name, detail=None):
    evidence["checks"].append({"id":name,"result":"PASS","detail":detail})
    print(name+": PASS",flush=True)
def gateway(path, expected, mode):
    req=urllib.request.Request("http://127.0.0.1:8080"+path,headers={"Host":"demo.example.test","Authorization":"Bearer PRIVACY_CANARY_AUTH_9182","Cookie":"session=PRIVACY_CANARY_COOKIE_9182","X-Aegis-Request-ID":"spoofed-id"})
    try:
        with urllib.request.urlopen(req,timeout=5) as r: code,h=r.status,r.headers; r.read(8192)
    except urllib.error.HTTPError as r: code,h=r.code,r.headers; r.read(8192)
    assert code==expected,(code,expected)
    assert h.get("X-Aegis-Mode")==mode
    assert h.get("X-Aegis-Request-ID") and h.get("X-Aegis-Request-ID")!="spoofed-id"
    return h["X-Aegis-Request-ID"]
try:
    call("/system/status",expected=401); check("unauthenticated_admin_denied")
    credential=CREDENTIAL_FILE
    logs=subprocess.check_output(COMPOSE+["logs","--no-log-prefix","controller"],cwd=ROOT,text=True)
    tokens=[]
    for line in logs.splitlines():
        try:
            entry=json.loads(line)
            if entry.get("event")=="local_bootstrap_token":tokens.append(entry["token"])
        except ValueError: pass
    if credential.exists():
        password=credential.read_text()
        response=call("/auth/login",{"password":password})
    else:
        assert tokens,"No fresh bootstrap token; use a dedicated demo installation."
        password=secrets.token_urlsafe(24)
        response=call("/auth/bootstrap",{"token":tokens[-1],"password":password})
        fd=os.open(credential,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w") as f:f.write(password)
    csrf=response["csrf_token"]; check("owner_session_enrolled")
    current=call("/sites/site_demo/policy")
    assert current["policy"]["requested_mode"]=="observe","Run from Observe mode"
    cursor=0
    # The API returns oldest-first pages. Start after retained history so a
    # repeated acceptance run cannot mistake the first page for fresh events.
    for _ in range(501):
        page=call("/sites/site_demo/events?limit=100&cursor="+str(cursor))
        cursor=page["cursor"]
        if len(page["items"])<100:
            break
    else:
        raise AssertionError("Retained event history exceeded its paging budget")
    request_id=gateway("/test-pattern?query=1%27%20OR%20%271%27%3D%271",200,"observe")
    gateway("/catalog?query=PRIVACY_CANARY_QUERY_9182",200,"observe")
    deadline=time.monotonic()+15
    records=[]
    while True:
        page=call("/sites/site_demo/events?limit=100&cursor="+str(cursor))
        cursor=page["cursor"]
        records.extend(page["items"])
        correlated=[x["event"] for x in records if x["event"]["request_id"]==request_id]
        if (any("942100" in e["rule_ids"] for e in correlated)
                and any(e["source"]=="caddy-access" for e in correlated)):
            break
        if time.monotonic()>=deadline:
            raise AssertionError("Timed out waiting for the request's CRS 942100 and access events")
        time.sleep(.25)
    assert any("942100" in e["rule_ids"] for e in correlated),correlated
    assert any(e["source"]=="caddy-access" for e in correlated)
    check("observe_expected_rule_and_access_correlated",{"rule_id":"942100"})
    all_text=json.dumps(records)
    assert "PRIVACY_CANARY" not in all_text
    check("default_evidence_excludes_secret_canaries")
    candidate=current["policy"].copy(); candidate["requested_mode"]="protect";candidate["parent_revision"]=current["digest"]
    candidate["metadata"]={"rationale":"Synthetic acceptance Protect trial", "requested_by":"owner"}
    proof=call("/sites/site_demo/policies/validate",candidate)
    assert proof["fixture_result"]=="PASS",proof
    check("independent_protect_fixture_pass",{"report_digest":proof["report"]["canonical_sha256"]})
    draft=call("/sites/site_demo/policies",candidate,expected=201)
    key="test-"+secrets.token_hex(16)
    headers={"If-Match":'"'+current["digest"]+'"',"Idempotency-Key":key}
    body={"reason":"Synthetic acceptance Protect trial", "acknowledge_disruption_risk":True}
    receipt=call("/sites/site_demo/policies/"+draft["digest"]+"/activate",body,headers)
    again=call("/sites/site_demo/policies/"+draft["digest"]+"/activate",body,headers)
    assert again==receipt
    check("activation_retry_is_idempotent")
    gateway("/test-pattern?query=1%27%20OR%20%271%27%3D%271",403,"protect")
    gateway("/catalog?query=ordinary",200,"protect")
    check("protect_denies_pattern_preserves_benign")
    subprocess.run(COMPOSE+["stop","controller"],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
    gateway("/test-pattern?query=1%27%20OR%20%271%27%3D%271",403,"protect")
    subprocess.run(COMPOSE+["restart","gateway"],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
    for _ in range(30):
        try:gateway("/test-pattern?query=1%27%20OR%20%271%27%3D%271",403,"protect");break
        except (OSError,AssertionError):time.sleep(.25)
    else:raise AssertionError("Gateway did not recover Protect from disk")
    check("controller_loss_and_gateway_restart_preserve_protect")
    subprocess.run(COMPOSE+["start","controller"],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
    time.sleep(2)
    assert call("/system/status")["gateway_healthy"]
    headers={"If-Match":'"'+draft["digest"]+'"',"Idempotency-Key":"test-rollback-"+secrets.token_hex(16)}
    call("/sites/site_demo/policies/"+current["digest"]+"/rollback",{"reason":"Restore Observe after synthetic acceptance", "acknowledge_disruption_risk":True},headers)
    gateway("/test-pattern?query=1%27%20OR%20%271%27%3D%271",200,"observe")
    check("tested_rollback_restores_observe")
    inspect=json.loads(subprocess.check_output(["docker","inspect","aegis-community-controller-1","aegis-community-deployer-1","aegis-community-verifier-1"],text=True))
    controller,deployer,verifier=inspect
    assert not any(m["Destination"]=="/run/gateway" for m in controller["Mounts"])
    assert deployer["HostConfig"]["NetworkMode"]=="none"
    assert all(not m["Destination"].endswith("docker.sock") for c in inspect for m in c["Mounts"])
    assert list(verifier["NetworkSettings"]["Networks"])==["aegis-community_fixture_net"]
    check("privilege_and_fixture_network_boundaries")
    evidence["overall"]="PASS"
except Exception as e:
    evidence["overall"]="FAIL"; evidence["error"]=str(e)[:1800]
    raise
finally:
    evidence["completed_at"]=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    evidence["limitations"]=["Local ARM64 Docker Desktop run, not independent installation or production certification.","Trusted bundled fixture only; no untrusted repository execution.","No TLS, throughput, expiry, independent security review, or AI provider GUI claim."]
    (ROOT/"docs/evidence/demo-acceptance.json").write_text(json.dumps(evidence,indent=2)+"\n")
