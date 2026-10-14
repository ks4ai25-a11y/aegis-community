#!/usr/bin/env python3
"""Exercise the local owner scan API without executing repository code."""
import http.cookiejar,json,pathlib,secrets,sys,time,urllib.request
from local_context import CREDENTIAL_FILE
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from contracts.generated.research_client import ResearchClient
report={'schema_version':'1.0','scope':'local-owner-offline-scanner-api','started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'checks':[]}
def check(name):
 report['checks'].append({'id':name,'result':'PASS'});print(name+': PASS',flush=True)
try:
 jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
 req=urllib.request.Request('http://127.0.0.1:7410/api/v1/auth/login',data=json.dumps({'password':CREDENTIAL_FILE.read_text()}).encode(),headers={'Content-Type':'application/json'})
 with opener.open(req,timeout=10) as r:csrf=json.load(r)['csrf_token']
 cookie=next(c.value for c in jar if c.name=='aegis_session');client=ResearchClient(session_cookie=cookie,csrf_token=csrf)
 repo=client.connectRepository({'app_id':'app_demo','asset_id':'safe','acknowledge_read_only':True})
 body={'schema_version':'1.0','app_id':'app_demo','repository_id':repo['repository_id'],'map_digest':repo['map_digest'],'mode':'repo_offline','tool_ids':['bandit'],'tool_timeout_seconds':30}
 key='scan-http-'+secrets.token_hex(16)
 first=client.createScan(body,key);again=client.createScan(body,key);assert first==again and first['state']=='queued'
 check('generated_client_enqueue_replay_is_exact')
 try:client.createScan({**body,'tool_timeout_seconds':31},key)
 except RuntimeError as e:assert 'HTTP 409' in str(e)
 else:raise AssertionError('Changed retry accepted')
 check('changed_idempotent_request_is_refused')
 status=client.getScan(first['job_id']);assert status['job']==first and status['execution_admission']=='not_claimed'
 check('queued_owner_status_does_not_claim_execution')
 assert any(j['job_id']==first['job_id'] for j in client.listScans()['items'])
 check('owned_job_is_listed')
 try:client.getScanResult(first['job_id'])
 except RuntimeError as e:assert 'HTTP 409' in str(e)
 else:raise AssertionError('Pending job returned success result')
 check('pending_result_is_explicitly_unavailable')
 cancelled=client.cancelScan(first['job_id'],{});assert cancelled['job']['state']=='cancelled' and cancelled['job']['cancel_requested']
 assert cancelled['execution_admission']=='unconfirmed'
 assert client.cancelScan(first['job_id'],{})==cancelled
 check('cancel_is_idempotent_and_does_not_assert_cleanup')
 try:client.createScan({**body,'owner_id':'other'},'scan-invalid-'+secrets.token_hex(16))
 except RuntimeError as e:assert 'HTTP 400' in str(e)
 else:raise AssertionError('Caller-selected owner accepted')
 check('caller_selected_owner_is_refused')
 for name,value in [('ScannerJobInputV1',body),('ScannerJobV1',first),('ScannerJobStatusV1',status),('ScannerJobListV1',{'items':[first]})]:
  (ROOT/'contracts/samples'/f'{name}.json').write_text(json.dumps(value,indent=2)+'\n')
 report['overall']='PASS'
except Exception as e:
 report['overall']='FAIL';report['error']=str(e)[:1000];raise
finally:
 report['completed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
 report['limitations']=['Named local demo and native component tests only; no independent installation claim.','This live check queues and cancels a static job; actual execution/result reads are checked separately with native operator-UID fixtures.','Cancellation does not confirm resource cleanup or release held admission.','Findings detail API/UI, background worker pairing, independent cleanup verification, offline databases and remaining v4 release gates are unfinished.']
 (ROOT/'docs/evidence/scanner-owner-api-live-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
