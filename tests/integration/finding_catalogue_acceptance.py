#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Explicit read-only catalogue checks against the named local synthetic demo."""
import datetime,http.cookiejar,json,os,pathlib,sys,urllib.error,urllib.parse,urllib.request
from local_context import CREDENTIAL_FILE
if not __debug__ or os.environ.get('AEGIS_LIVE_CATALOGUE_TEST')!='1':raise SystemExit('Set AEGIS_LIVE_CATALOGUE_TEST=1 with assertions enabled')
ROOT=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from contracts.generated.research_client import ResearchClient
jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar))
request=urllib.request.Request('http://127.0.0.1:7410/api/v1/auth/login',data=json.dumps({'password':CREDENTIAL_FILE.read_text()}).encode(),headers={'Content-Type':'application/json'})
with opener.open(request,timeout=10) as response:csrf=json.load(response)['csrf_token']
cookie=next(c.value for c in jar if c.name=='aegis_session');client=ResearchClient(session_cookie=cookie,csrf_token=csrf);checks=[]
def check(name):checks.append({'id':name,'result':'PASS'});print(name+': PASS',flush=True)
listing=client.listFindingCatalogue({'limit':20})
assert listing['schema_version']=='1.0' and listing['scope']=='retained_static_observations' and 0<=listing['retained_result_count']<=1000 and 0<=listing['jobs_without_result']<=1000
if listing['retained_result_count']==0:assert 'result' not in listing and 'findings' not in listing and listing['next_cursor']==''
else:
 result=client.getScanResult(listing['findings']['job_id']);assert result==listing['result'] and result['document']['owner_id']==listing['owner_id'];assert listing['findings']['result_digest']==result['result_digest']
check('generated_catalogue_client_retains_explicit_result_and_unavailable_job_scopes')
for query in ({'limit':0},{'limit':21},{'category':'confirmed_exploit'},{'since':'tomorrow'},{'since':'2026-01-02T00:00:00Z','until':'2026-01-01T00:00:00Z'},{'cursor':'invalid'}):
 try:client.listFindingCatalogue(query)
 except RuntimeError as error:assert 'HTTP 400' in str(error)
 else:raise AssertionError('Invalid catalogue scope accepted')
check('packaged_catalogue_rejects_invalid_filters_time_ranges_and_cursors')
def refuse(query,status,authenticated=True):
 headers={'Cookie':'aegis_session='+cookie} if authenticated else {};transport=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 try:transport.open(urllib.request.Request('http://127.0.0.1:7410/api/v1/findings/catalogue'+query,headers=headers),timeout=10)
 except urllib.error.HTTPError as error:assert error.code==status and error.headers.get('Cache-Control')=='no-store'
 else:raise AssertionError('Catalogue authority boundary returned success')
refuse('?owner_id=another-owner',400);refuse('?limit=2&limit=3',400);check('packaged_catalogue_refuses_caller_selected_owners_and_repeated_filters')
refuse('',401,False);refuse('?repository_id=00000000-0000-7000-8000-000000000000',404);check('packaged_catalogue_requires_owner_session_and_owned_repository')
future=client.listFindingCatalogue({'since':'9998-01-01T00:00:00Z'});assert future['retained_result_count']==0 and future['jobs_without_result']==listing['jobs_without_result'];check('result_time_selection_preserves_missing_execution_count')
again=client.listFindingCatalogue({'limit':20});assert again==listing;check('read_only_catalogue_preserves_immutable_roster_and_existing_state')
report={'schema_version':'1.0','status':'PASS','scope':'Named local demo generated-client/read-only catalogue boundaries; no new scanner executions or independent installation claim','recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':checks,'actual_page':listing,'new_scanner_jobs':False,'cleanup_admission_released':False}
path=pathlib.Path(os.environ.get('AEGIS_CATALOGUE_LIVE_EVIDENCE',str(ROOT/'docs/evidence/finding-catalogue-live-acceptance.json')));path.write_text(json.dumps(report,indent=2)+'\n');print('packaged_catalogue_checks: '+str(len(checks)),flush=True)
