#!/usr/bin/env python3
"""Actual local owner-scoped repository registration and read-only mount evidence."""
import hashlib,http.cookiejar,json,pathlib,subprocess,sys,time,urllib.request,urllib.error
from local_context import CREDENTIAL_FILE
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from contracts.generated.research_client import ResearchClient
checks=[]
report={'schema_version':'1.0','scope':'local-provisioned-read-only-scanner-fixtures','started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'checks':checks}
def check(name,detail=None):
 checks.append({'id':name,'result':'PASS','detail':detail});print(name+': PASS',flush=True)
try:
 jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
 req=urllib.request.Request('http://127.0.0.1:7410/api/v1/auth/login',data=json.dumps({'password':CREDENTIAL_FILE.read_text()}).encode(),headers={'Content-Type':'application/json'})
 with opener.open(req,timeout=10) as r:csrf=json.load(r)['csrf_token']
 cookie=next(c.value for c in jar if c.name=='aegis_session')
 client=ResearchClient(session_cookie=cookie,csrf_token=csrf)
 assets=client.listRepositoryAssets()['asset_ids'];assert assets==['safe','vulnerable'],assets
 check('only_provisioned_fixture_asset_ids_available')
 body={'app_id':'app_demo','asset_id':'vulnerable','acknowledge_read_only':True}
 started=time.monotonic();first=client.connectRepository(body);elapsed_ms=round((time.monotonic()-started)*1000,2);again=client.connectRepository(body)
 assert first['repository_id']==again['repository_id'] and first['map_digest']==again['map_digest']
 check('reconnect_preserves_repository_and_content_identity')
 m=client.getApplicationMap(first['repository_id']);assert m['content_digest']==first['map_digest']
 fixture=ROOT/'alpha/fixtures/scanners/vulnerable'
 expected={p.name:'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest() for p in fixture.iterdir() if p.is_file()}
 assert {f['path']:f['digest'] for f in m['files']}==expected
 assert not m['commit_sha'] and any('Commit identity unavailable' in s for s in m['unknowns'])
 assert not m['routes'] and not m['auth_boundaries']
 check('live_map_matches_file_bytes_and_preserves_unknowns',{'map_digest':m['content_digest'],'file_count':len(m['files']),'input_bytes':sum(f['size'] for f in m['files']),'connect_elapsed_ms':elapsed_ms})
 assert 'ghp_' not in json.dumps(m) and 'THIS_SCRIPT_MUST_NEVER_EXECUTE' not in json.dumps(m)
 check('application_map_does_not_publish_fixture_secret_or_script_contents')
 for asset in ['../vulnerable','/etc','https://example.test','safe/../vulnerable']:
  try:client.connectRepository({**body,'asset_id':asset})
  except RuntimeError as e:assert str(e)=="Aegis API rejected request with HTTP 400"
  else:raise AssertionError('host path or URL accepted')
 check('host_paths_urls_and_traversal_rejected')
 inspect=json.loads(subprocess.check_output(['docker','inspect','aegis-community-controller-1']))[0]
 mount=next(v for v in inspect['Mounts'] if v['Destination']=='/opt/aegis/repositories')
 assert mount['Type']=='bind' and mount['RW'] is False
 assert all('docker.sock' not in v['Destination'] for v in inspect['Mounts'])
 check('controller_source_mount_is_read_only_and_has_no_docker_socket')
 write_probe=subprocess.run(['docker','exec','aegis-community-controller-1','sh','-c','touch /opt/aegis/repositories/vulnerable/.aegis-write-probe'],capture_output=True,timeout=5)
 if write_probe.returncode==0:
  (fixture/'.aegis-write-probe').unlink(missing_ok=True)
  raise AssertionError('Repository mount permitted a write')
 assert b'Read-only file system' in write_probe.stderr,write_probe.stderr[:512]
 check('repository_mount_rejects_actual_write_attempt')
 assert any(r['repository_id']==first['repository_id'] for r in client.listRepositories()['items'])
 check('registered_repository_is_durable_owner_state')
 (ROOT/'contracts/samples/RepositoryV1.json').write_text(json.dumps(first,indent=2)+'\n')
 (ROOT/'contracts/samples/ApplicationMapV1.json').write_text(json.dumps(m,indent=2)+'\n')
 report['overall']='PASS'
except Exception as e:
 report['overall']='FAIL';report['error']=str(e)[:1800];raise
finally:
 report['completed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
 report['limitations']=['Single durably bound mount owner, app_demo and provisioned local read-only roots only.','No remote clone, credential import, arbitrary repository code execution or durable scanner execution claim.','Commit metadata is not proof of a clean checkout; conventional .git metadata only.','Full framework extraction, source snapshotting and external review remain pending.']
 (ROOT/'docs/evidence/repository-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
