#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Operator-launched pinned tools; only the trusted bundled inert fixture is mounted."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import hashlib,json,pathlib,resource,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
TOOLS=json.loads((ROOT/'tools/scanners.lock.json').read_text())['tools']
BINARY=ROOT/'bin/aegis-research'
report={'schema_version':'1.0','scope':'trusted-bundled-static-fixtures','checks':[],'limitations':['Publisher signatures and licence review pending.','Missing offline databases are tool_error, never no findings.','No repository code or package scripts executed.']}
def limit_output(): resource.setrlimit(resource.RLIMIT_FSIZE,(8<<20,8<<20))
for tool in TOOLS:
 for fixture in ['vulnerable','safe']:
  src=(ROOT/'alpha/fixtures/scanners'/fixture).resolve()
  data=b''.join(p.name.encode()+b'\0'+p.read_bytes() for p in sorted(src.iterdir()))
  input_digest='sha256:'+hashlib.sha256(data).hexdigest()
  invocation=json.loads(subprocess.check_output([str(BINARY),'invocation',tool['id']]))
  args=['docker','run','--rm','--pull=never','--network=none','--read-only','--user=10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=768m','--cpus=1','--log-driver=none','--tmpfs','/tmp:rw,nosuid,size=96m,uid=10001,gid=10001','-e','HOME=/tmp','-e','SEMGREP_SEND_METRICS=off','-v',str(src)+':/src:ro','-v',str(ROOT/'alpha/rules')+':/rules:ro',tool['image']]+invocation['args']
  with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
   started=time.monotonic()
   try:
    run=subprocess.run(args,stdout=out,stderr=err,timeout=125,preexec_fn=limit_output)
    out.seek(0);raw=out.read((8<<20)+1);err.seek(0);diagnostics=err.read(4096).decode(errors='replace')
    result={'id':tool['id']+'-'+fixture,'tool_version':tool['version'],'image_digest':tool['image'].split('@')[1],'input_digest':input_digest,'exit_code':run.returncode,'elapsed_seconds':round(time.monotonic()-started,3)}
    if run.returncode not in invocation['finding_exit_codes']:
     result.update(status='tool_error',diagnostic=diagnostics[:1000])
    else:
     parsed=subprocess.run([str(BINARY),'parse',tool['id'],tool['version'],result['image_digest'],input_digest],input=raw,capture_output=True)
     normalized=json.loads(parsed.stdout)
     result.update(status=normalized['status'],findings=normalized['findings'],diagnostics=normalized['diagnostics'])
     if 'sbom' in normalized:result['sbom']=normalized['sbom']
     assert 'ghp_' not in json.dumps(result),'fake credential match retained'
     if parsed.returncode:result['status']='tool_error'
   except subprocess.TimeoutExpired:
    result={'id':tool['id']+'-'+fixture,'status':'tool_error','diagnostic':'timeout; no findings conclusion'}
   report['checks'].append(result)
   print(result['id']+': '+result['status']+' findings='+str(len(result.get('findings',[]))),flush=True)
report['completed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
# The run must show the tools actually work on the fixtures: static tools find
# more in the vulnerable fixture than in the safe one, Syft produces an SBOM.
# OSV/Trivy without a provisioned database must be tool_error, never "clean".
by={c['id']:c for c in report['checks']}
failures=[]
for tool in TOOLS:
 vul,safe=by.get(tool['id']+'-vulnerable',{}),by.get(tool['id']+'-safe',{})
 if tool['id'] in ('semgrep_ce','gitleaks','bandit'):
  if vul.get('status')=='tool_error' or len(vul.get('findings',[]))<=len(safe.get('findings',[])):
   failures.append(tool['id']+': vulnerable fixture did not produce more findings than safe')
 elif tool['id']=='syft':
  if vul.get('status')=='tool_error' or not vul.get('sbom'):
   failures.append('syft: no SBOM produced')
 elif tool['id'] in ('osv_v2','trivy'):
  if vul.get('status') not in ('tool_error','completed_stale_db','completed'):
   failures.append(tool['id']+': unexpected status '+str(vul.get('status')))
report['result']='FAIL' if failures else 'PASS'
report['failures']=failures
if failures:
 # Keep the last good evidence; print what failed instead.
 raise SystemExit('Scanner acceptance FAILED: '+'; '.join(failures))
(ROOT/'docs/evidence/scanner-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
