#!/usr/bin/env python3
"""Real local fixture job acceptance. Only affects named Aegis demo services."""
import http.cookiejar,json,pathlib,secrets,subprocess,time,urllib.request,urllib.error
from local_context import CREDENTIAL_FILE
ROOT=pathlib.Path(__file__).resolve().parents[2]
COMPOSE=['docker','compose','-f',str(ROOT/'deploy/compose.demo.yaml')]
http=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf=''
report={'schema_version':'1.0','scope':'local-bundled-synthetic-job-worker','checks':[],'started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
def call(path,body=None,headers=None,expected=200):
 h={'Content-Type':'application/json','X-CSRF-Token':csrf,**(headers or {})}
 req=urllib.request.Request('http://127.0.0.1:7410/api/v1'+path,data=None if body is None else json.dumps(body).encode(),headers=h)
 try:
  with http.open(req,timeout=10) as r:code,raw=r.status,r.read(131072)
 except urllib.error.HTTPError as r:code,raw=r.code,r.read(131072)
 assert code==expected,(path,code,raw[:1000]);return json.loads(raw)
def check(name,detail=None):
 report['checks'].append({'id':name,'result':'PASS','detail':detail});print(name+': PASS',flush=True)
def grant():
 g=call('/scope-grants',{'app_id':'app_demo','mode':'test_lab','fixture_id':'crs-synthetic-sqli-pattern-v1','lifetime_minutes':10},expected=201)
 return call('/scope-grants/'+g['grant']['scope_grant_id']+'/approve',{'approved_digest':g['approved_digest'],'acknowledge_test_scope':True})
def enqueue(g,k=None):
 current=call('/sites/site_demo/policy')
 data={'schema_version':'1.0','app_id':'app_demo','scope_grant_id':g['grant']['scope_grant_id'],'scope_digest':g['approved_digest'],'fixture_id':'crs-synthetic-sqli-pattern-v1','policy_digest':current['digest']}
 h={'Idempotency-Key':k or 'acceptance-'+secrets.token_hex(12)}
 return call('/verifications',data,h,202),data,h
def wait(j,terminal=True,seconds=25):
 until=time.monotonic()+seconds
 while time.monotonic()<until:
  value=call('/verifications/'+j['job_id'])
  if terminal and value['state'] not in ['queued','running']:return value
  if not terminal and value['state']=='running':return value
  if not terminal and value['state'] not in ['queued','running']:raise AssertionError('Job finished before crash/revoke test could run')
  time.sleep(.05)
 raise AssertionError('Durable job did not reach expected state')
try:
 password=CREDENTIAL_FILE.read_text()
 csrf=call('/auth/login',{'password':password})['csrf_token']
 assert call('/health/ready')['ready']
 g=grant();j,data,h=enqueue(g)
 retry=call('/verifications',data,h,202);assert retry['job_id']==j['job_id'];check('scoped_enqueue_is_idempotent')
 done=wait(j);assert done['state']=='success',done
 proof=call('/verify/reports/'+done['report_digest'])
 assert proof['job_id']==j['job_id'] and proof['scope_grant_id']==g['grant']['scope_grant_id'] and proof['scope_digest']==g['approved_digest']
 assert proof['overall']=='PASS' and '942100' in proof['checks'][1]['baseline_rule_ids'] and '942100' in proof['checks'][1]['rule_ids']
 check('real_independent_report_binds_job_scope_and_controls',{'job_id':j['job_id'],'report_digest':done['report_digest']})
 exhausted=call('/scope-grants/'+g['grant']['scope_grant_id']);assert exhausted['requests_remaining']==0
 call('/verifications',data,{'Idempotency-Key':'exhausted-'+secrets.token_hex(12)},403);check('scope_request_budget_is_enforced')
 g2=grant();j2,_,_=enqueue(g2);wait(j2,terminal=False)
 call('/scope-grants/'+g2['grant']['scope_grant_id']+'/revoke',{})
 cancelled=wait(j2);assert cancelled['state']=='cancelled' and not cancelled.get('report_digest'),cancelled
 check('revocation_interrupts_real_running_fixture')
 g3=grant();j3,_,_=enqueue(g3);wait(j3,terminal=False)
 subprocess.run(COMPOSE+['kill','-s','SIGKILL','controller'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
 subprocess.run(COMPOSE+['start','controller'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
 until=time.monotonic()+10
 while True:
  try:call('/health/live');break
  except (OSError,AssertionError):
   assert time.monotonic()<until,'controller did not restart';time.sleep(.2)
 lost=wait(j3,seconds=25);assert lost['state']=='timeout' and lost['error_code']=='WORKER_LEASE_EXPIRED' and not lost.get('report_digest'),lost
 check('controller_crash_expires_lease_without_false_success')
 history=call('/verifications')['items'];assert any(x['job_id']==j['job_id'] and x['report_digest']==done['report_digest'] for x in history)
 proof_again=call('/verify/reports/'+done['report_digest']);assert proof_again==proof
 check('job_and_owned_report_survive_controller_restart')
 records=[item['record'] for item in call('/audit')['items']]
 for job,actions in [(j,['research.enqueue','research.claim','research.finished']),(j3,['research.enqueue','research.claim','research.recovered'])]:
  observed={r['action'] for r in records if r['object_id']==job['job_id']}
  assert set(actions)<=observed,(job['job_id'],observed)
 claims=[r for r in records if r['action']=='research.claim' and r['object_id']==j['job_id']]
 assert len(claims)==1 and claims[0]['data']['requests_reserved']==4 and claims[0]['data']['scope_digest']==g['approved_digest']
 assert all('lease_token' not in json.dumps(r) for r in records)
 subprocess.run(COMPOSE+['exec','-T','controller','aegisctl','audit','verify'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
 check('durable_claim_and_crash_reconciliation_are_audited',{'requests_reserved':4,'local_hash_chain_verified':True})

 report['overall']='PASS'
except Exception as e:
 report['overall']='FAIL';report['error']=str(e)[:1800];raise
finally:
 report['completed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
 report['limitations']=['Only bundled trusted fixture and local ARM64 Docker Desktop tested.','No arbitrary staging target, untrusted code execution, signed scope authority or external security review claim.','Policy preview still uses its separate synchronous fixed fixture path.']
 (ROOT/'docs/evidence/scoped-jobs-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
