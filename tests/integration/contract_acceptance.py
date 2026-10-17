#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Validate live owner-scoped API payloads and fixtures with Draft 2020-12 schemas."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import http.cookiejar,json,pathlib,sys,urllib.request
from local_context import CREDENTIAL_FILE
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
import jsonschema
from contracts.generated.research_client import ResearchClient
schemas={p.stem:json.loads(p.read_text()) for p in (ROOT/'contracts/schemas').glob('*.json')}
for s in schemas.values():jsonschema.Draft202012Validator.check_schema(s)
jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
password=CREDENTIAL_FILE.read_text()
request=urllib.request.Request('http://127.0.0.1:7410/api/v1/auth/login',data=json.dumps({'password':password}).encode(),headers={'Content-Type':'application/json'})
with opener.open(request,timeout=10) as r:csrf=json.load(r)['csrf_token']
cookie=next(c.value for c in jar if c.name=='aegis_session')
client=ResearchClient(session_cookie=cookie,csrf_token=csrf)
checks=[]
def validate(name,value):
 jsonschema.Draft202012Validator(schemas[name]).validate(value)
 checks.append({'schema':name,'result':'PASS'});print(name+': PASS',flush=True)
validate('RepositoryAssetListV1',client.listRepositoryAssets())
repos=client.listRepositories();validate('RepositoryListV1',repos)
if repos['items']:
 repository=client.getRepository(repos['items'][0]['repository_id']);validate('RepositoryV1',repository)
 validate('ApplicationMapV1',client.getApplicationMap(repository['repository_id']))
validate('ScopeGrantListV1',client.listScopeGrants())
job_list=client.listVerifications();validate('ResearchJobListV1',job_list)
success=next(j for j in job_list['items'] if j['state']=='success')
job=client.getVerification(success['job_id']);validate('ResearchJobV1',job)
grant=client.getScopeGrant(job['scope_grant_id']);validate('ScopeGrantRecordV1',grant)
proof=client.getVerificationReport(job['report_digest']);validate('VerificationReportV1',proof)
for name,value in [('ResearchJobV1',job),('ScopeGrantRecordV1',grant),('VerificationReportV1',proof)]:
 (ROOT/'contracts/samples'/f'{name}.json').write_text(json.dumps(value,indent=2)+'\n')
scan=json.loads((ROOT/'docs/evidence/scanner-acceptance.json').read_text())
for check in scan['checks']:
 for finding in check.get('findings',[]):validate('FindingV1',finding)
# Adversarial inputs must fail the same schema checks.
for name,value in [('RepositoryConnectionRequestV1',{'app_id':'app_demo','asset_id':'../private','acknowledge_read_only':True}),('RepositoryConnectionRequestV1',{'app_id':'app_demo','asset_id':'safe','acknowledge_read_only':False}),('ScopeGrantDraftRequestV1',{'app_id':'app_demo','mode':'production_intrusive','fixture_id':'crs-synthetic-sqli-pattern-v1','lifetime_minutes':10}),('ScopeGrantApprovalRequestV1',{'approved_digest':'sha256:'+'0'*64,'acknowledge_test_scope':False}),('VerificationReportV1',{'schema_version':'1.0','overall':'PASS','checks':[]})]:
 assert not jsonschema.Draft202012Validator(schemas[name]).is_valid(value),name
 checks.append({'schema':name,'negative_result':'REJECTED'})
report={'schema_version':'1.0','overall':'PASS','validator':'jsonschema 4.26.0 Draft202012Validator','checks':checks,'limitations':['Implemented research surface only; complete v4 contract catalogue remains incomplete.','Bindings are not a substitute for runtime semantic authorization and control validation.']}
(ROOT/'docs/evidence/contract-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
