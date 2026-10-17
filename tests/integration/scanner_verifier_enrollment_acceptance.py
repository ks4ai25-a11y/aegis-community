#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Verify local observer-role delivery without reading credential contents."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import hashlib,json,pathlib,re,secrets,subprocess,time,urllib.request,urllib.error
ROOT=pathlib.Path(__file__).resolve().parents[2]
COMPOSE=['docker','compose','-f',str(ROOT/'deploy/compose.demo.yaml'),'exec','-T','controller']
name='acceptance-verifier-'+secrets.token_hex(8);worker=name+'-worker'
credential_dir='/var/lib/aegis/'+name+'.credentials'
path=credential_dir+'/observer.token';worker_path=credential_dir+'/worker.token';other_path=credential_dir+'/other.token'
engine='sha256:'+hashlib.sha256(b'synthetic-live-enrollment-engine-scope').hexdigest()
registry='sha256:'+hashlib.sha256(b'synthetic-live-enrollment-registry-scope').hexdigest()
report={'schema_version':'1.0','scope':'named-demo-local-cleanup-observer-identity-only','started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'checks':[]}
created=False;worker_created=False;directory_created=False
def run(args,expected=0):
 result=subprocess.run(COMPOSE+args,capture_output=True,timeout=20)
 assert result.returncode==expected,'Local observer command returned unexpected status'
 assert not re.search(rb'(?<![a-zA-Z0-9])[0-9a-f]{64}(?![a-zA-Z0-9])',result.stdout),'Credential-shaped data in CLI output'
 return result.stdout.decode().strip()
def check(name):report['checks'].append({'id':name,'result':'PASS'});print(name+': PASS',flush=True)
try:
 run(['mkdir','-m','700',credential_dir]);directory_created=True
 output=run(['aegisctl','scanner-verifier','enroll',name,'1',engine,registry,path]);created=True
 assert name in output and 'credential written privately' in output and 'metadata only' in output
 check('local_operator_enrolls_observer_without_printing_credential')
 output=run(['aegisctl','scanner-verifier','probe',path]);assert name in output and 'authenticated for owner' in output and 'metadata only' in output
 check('distinct_private_observer_identity_authenticates')
 assert run(['stat','-c','%a',path])=='600' and run(['stat','-c','%s',path])=='65'
 run(['test','-f',path]);run(['test','!','-L',path])
 check('observer_credential_is_private_regular_file')
 run(['aegisctl','scanner-worker','probe',path],1)
 check('observer_credential_cannot_authenticate_as_worker')
 run(['aegisctl','scanner-worker','enroll',worker,'1',worker_path]);worker_created=True
 run(['aegisctl','scanner-verifier','probe',worker_path],1)
 check('worker_credential_cannot_authenticate_as_observer')
 run(['aegisctl','scanner-verifier','enroll',name+'-duplicate','1',engine,registry,path],1)
 run(['aegisctl','scanner-verifier','revoke',name+'-duplicate'],1)
 check('existing_credential_refuses_new_identity_without_overwrite')
 run(['aegisctl','scanner-verifier','enroll',name,'1',engine,registry,other_path],1)
 run(['test','!','-e',other_path])
 check('retained_identity_cannot_be_reenrolled')
 run(['aegisctl','scanner-verifier','enroll',name+'-invalid','1','unix:///not-a-digest',registry,other_path],1)
 run(['test','!','-e',other_path])
 check('non_digest_scope_is_refused_without_credential_artifact')
 req=urllib.request.Request('http://127.0.0.1:7410/internal/v1/scanner/verifier/identity',data=b'{}',headers={'Content-Type':'application/json'})
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args,**kwargs):return None
 opener=urllib.request.build_opener(NoRedirect())
 try:
  with opener.open(req,timeout=5) as response:raise AssertionError('Private verifier operation exposed on dashboard')
 except urllib.error.HTTPError as error:assert error.code==404
 check('observer_protocol_is_not_exposed_on_dashboard_listener')
 run(['aegisctl','scanner-verifier','revoke',name]);run(['aegisctl','scanner-verifier','revoke',name]);run(['aegisctl','scanner-verifier','probe',path],1)
 check('observer_revocation_is_idempotent_and_denies_probe')
 output=run(['aegisctl','scanner-worker','probe',worker_path]);assert worker in output
 check('observer_revocation_does_not_revoke_worker_identity')
 run(['aegisctl','audit','verify'])
 check('observer_mutations_preserve_local_audit_chain')
 run(['aegisctl','scanner-worker','revoke',worker]);run(['rm',worker_path]);run(['rm',path]);run(['test','!','-e',path]);run(['test','!','-e',worker_path]);created=False;worker_created=False
 run(['rmdir',credential_dir]);directory_created=False
 check('revoked_fixture_credentials_removed')
 report['overall']='PASS'
except Exception as error:
 report['overall']='FAIL';report['error']=str(error)[:1000];raise
finally:
 if created:
  subprocess.run(COMPOSE+['aegisctl','scanner-verifier','revoke',name],capture_output=True,timeout=20)
  subprocess.run(COMPOSE+['rm',path],capture_output=True,timeout=20)
 if worker_created:
  subprocess.run(COMPOSE+['aegisctl','scanner-worker','revoke',worker],capture_output=True,timeout=20)
  subprocess.run(COMPOSE+['rm',worker_path],capture_output=True,timeout=20)
 if directory_created:subprocess.run(COMPOSE+['rmdir',credential_dir],capture_output=True,timeout=20)
 report['completed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
 report['limitations']=['Credential bytes were not read or exported by this harness.','Engine and registry digests in this enrollment fixture are synthetic; live engine state is not inspected here.','Scope-bound job context is tested separately through native parser/real-scanner fixtures.','This identity cannot release dispatch admission or establish resource absence. Dedicated deployed/background worker pairing, pending-request exclusion and independent release gates remain unfinished.']
 (ROOT/'docs/evidence/scanner-verifier-enrollment-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
