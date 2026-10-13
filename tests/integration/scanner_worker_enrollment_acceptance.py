#!/usr/bin/env python3
"""Local operator enrollment only; never reads or exports worker credentials."""
import json,pathlib,re,secrets,subprocess,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
COMPOSE=['docker','compose','-f',str(ROOT/'deploy/compose.demo.yaml'),'exec','-T','controller']
worker='acceptance-worker-'+secrets.token_hex(8)
path='/var/lib/aegis/'+worker+'.token'
checks=[]
report={'schema_version':'1.0','scope':'local-operator-worker-credential-delivery','checks':checks,'started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
def run(args,expected=0):
 result=subprocess.run(COMPOSE+args,capture_output=True,timeout=20)
 assert result.returncode==expected,'Local worker command failed with unexpected exit code'
 assert not re.search(rb'(?<![a-zA-Z0-9])[0-9a-f]{64}(?![a-zA-Z0-9])',result.stdout),'Credential-shaped bytes in CLI output'
 return result.stdout.decode().strip()
def check(name):
 checks.append({'id':name,'result':'PASS'});print(name+': PASS',flush=True)
created=False
try:
 output=run(['aegisctl','scanner-worker','enroll',worker,'1',path]);created=True
 assert worker in output and 'credential written privately' in output
 check('local_cli_enrolls_without_printing_credential')
 identity=run(['aegisctl','scanner-worker','probe',path]);assert worker in identity and 'authenticated for owner' in identity
 check('private_socket_probe_authenticates_enrolled_worker')
 assert run(['stat','-c','%a','/run/scanner'])=='700'
 assert run(['stat','-c','%a','/run/scanner/worker.sock'])=='600'
 names=['aegis-community-init-1','aegis-community-deployer-1','aegis-community-verifier-1','aegis-community-controller-1']
 mounts=subprocess.check_output(['docker','inspect','--format','{{json .Mounts}}',*names],timeout=20).decode().splitlines()
 assert len(mounts)==len(names)
 for name,line in zip(names,mounts):
  destinations={m['Destination'] for m in json.loads(line)}
  assert ('/run/scanner' in destinations)==(name=='aegis-community-controller-1')
  assert not any(p.endswith('docker.sock') for p in destinations)
 check('private_socket_permissions_and_service_mount_boundary')
 assert run(['stat','-c','%a',path])=='600'
 assert run(['stat','-c','%s',path])=='65'
 run(['test','-f',path]);run(['test','!','-L',path])
 check('credential_is_private_regular_file_with_expected_size')
 run(['aegisctl','scanner-worker','enroll',worker+'-duplicate','1',path],1)
 run(['aegisctl','scanner-worker','revoke',worker+'-duplicate'],1)
 check('existing_credential_refuses_new_role_without_overwrite')
 run(['aegisctl','scanner-worker','revoke',worker])
 run(['aegisctl','scanner-worker','revoke',worker])
 check('local_revocation_is_idempotent')
 run(['aegisctl','scanner-worker','probe',path],1)
 check('revocation_denies_private_socket_probe')
 run(['aegisctl','audit','verify'])
 check('worker_mutations_preserve_local_audit_chain')
 run(['rm',path]);run(['test','!','-e',path]);created=False
 check('revoked_test_credential_removed')
 report['overall']='PASS'
except Exception as error:
 report['overall']='FAIL';report['error']=str(error)[:1000];raise
finally:
 if created:
  subprocess.run(COMPOSE+['aegisctl','scanner-worker','revoke',worker],capture_output=True,timeout=20)
  subprocess.run(COMPOSE+['rm',path],capture_output=True,timeout=20)
 report['completed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
 report['limitations']=['Only local operator credential delivery on the named trusted demo checked.','Credential bytes were never read or exported by this acceptance harness.','Actual scanner execution, receipt ingestion and verified cleanup release remain unfinished.']
 (ROOT/'docs/evidence/scanner-worker-enrollment-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
