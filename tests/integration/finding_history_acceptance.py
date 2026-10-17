#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Opt-in read-only history refusals against the named synthetic local demo."""
import datetime,http.cookiejar,json,os,pathlib,sys,urllib.error,urllib.parse,urllib.request
from local_context import CREDENTIAL_FILE
if not __debug__ or os.environ.get('AEGIS_LIVE_FINDING_HISTORY_TEST')!='1':raise SystemExit('Set AEGIS_LIVE_FINDING_HISTORY_TEST=1 with assertions enabled')
ROOT=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from contracts.generated.research_client import ResearchClient
jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar))
req=urllib.request.Request('http://127.0.0.1:7410/api/v1/auth/login',data=json.dumps({'password':CREDENTIAL_FILE.read_text()}).encode(),headers={'Content-Type':'application/json'})
with opener.open(req,timeout=10) as response:csrf=json.load(response)['csrf_token']
cookie=next(c.value for c in jar if c.name=='aegis_session');client=ResearchClient(session_cookie=cookie,csrf_token=csrf)
checks=[]
def check(name):checks.append({'id':name,'result':'PASS'});print(name+': PASS',flush=True)
items=client.listScans()['items'];job=next((item for item in items if item['state'] in ('queued','cancelled')),None)
assert job,'An owned pending/cancelled scan fixture is required'
before=client.getScan(job['job_id']);record='sha256:'+'a'*64;result='sha256:'+'b'*64
try:client.getFindingTriageHistory({'record_id':record,'result_digest':result},job['job_id'])
except RuntimeError as error:assert 'HTTP 409' in str(error)
else:raise AssertionError('Unexecuted scan invented a complete owner review history')
check('generated_history_client_preserves_missing_source_evidence_as_unavailable')
base='/api/v1/scans/'+job['job_id']+'/finding-triage-history';query=urllib.parse.urlencode({'record_id':record,'result_digest':result})
def refusal(path,status,authenticated=True,expected_code=None):
 transport=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 headers={'Cookie':'aegis_session='+cookie} if authenticated else {}
 try:transport.open(urllib.request.Request('http://127.0.0.1:7410'+path,headers=headers),timeout=10)
 except urllib.error.HTTPError as error:
  assert error.code==status and error.headers.get('Cache-Control')=='no-store'
  payload=json.loads(error.read(8192))
  if expected_code:assert payload['error']['code']==expected_code
 else:raise AssertionError('History refusal returned success')
refusal(base+'?'+query,409,expected_code='RESULT_NOT_READY');check('packaged_history_explicitly_refuses_missing_immutable_result')
for suffix in ('','?record_id='+record,'?'+query+'&record_id='+record,'?'+query+'&unknown=1','?record_id=bad&result_digest='+result):refusal(base+suffix,400)
check('packaged_history_rejects_missing_repeated_unknown_and_malformed_scope')
refusal(base+'?'+query,401,False);check('packaged_history_requires_owner_session')
refusal('/api/v1/scans/00000000-0000-7000-8000-000000000000/finding-triage-history?'+query,404);check('packaged_history_does_not_reveal_unowned_job_state')
assert client.getScan(job['job_id'])==before;check('history_refusals_preserve_scan_and_admission_state')
report={'schema_version':'1.0','status':'PASS','scope':'Named local demo read-only owner history refusals; positive chain/export checked separately with native parser/HTTP and browser fixtures','recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':checks,'repository_code_executed':False,'new_reviews_written':False,'cleanup_admission_released':False}
path=pathlib.Path(os.environ.get('AEGIS_FINDING_HISTORY_LIVE_EVIDENCE',str(ROOT/'docs/evidence/finding-history-live-acceptance.json')));path.write_text(json.dumps(report,indent=2)+'\n')
print('packaged_history_checks: '+str(len(checks)),flush=True)
