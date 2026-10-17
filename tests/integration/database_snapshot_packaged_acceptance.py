#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Explicit local Docker snapshot proof; database bytes remain inside private Aegis storage."""
import hashlib,json,pathlib,re,secrets,subprocess,time,urllib.request,urllib.parse,datetime,os
ROOT=pathlib.Path(__file__).resolve().parents[2]
if not __debug__:raise SystemExit('Snapshot proof requires Python assertions enabled')
if os.environ.get('AEGIS_LIVE_SNAPSHOT_TEST')!='1':
 raise SystemExit('Set AEGIS_LIVE_SNAPSHOT_TEST=1 to create a private snapshot of the owned local Aegis demo')
# Resolve and freeze only a local Unix endpoint before touching any volume.
context=os.environ.get('DOCKER_CONTEXT','')
endpoint=os.environ.get('DOCKER_HOST','') if not context else ''
if not endpoint:
 context=context or subprocess.check_output(['docker','context','show'],text=True).strip()
 endpoint=subprocess.check_output(['docker','context','inspect',context,'--format','{{.Endpoints.docker.Host}}'],text=True).strip()
u=urllib.parse.urlsplit(endpoint)
if not (u.scheme=='unix' and not u.netloc and not u.query and not u.fragment and pathlib.PurePosixPath(u.path).is_absolute() and not any(ord(c)<32 for c in endpoint)):
 raise SystemExit('Snapshot proof requires a local Unix Docker endpoint')
docker_env={k:v for k,v in os.environ.items() if k not in {'DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION','DOCKER_TLS'}}
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
nonce=secrets.token_hex(16)
private='/var/lib/aegis/snapshot-proof-'+nonce
checks=[]
def command(args,timeout=60):
 assert args[0]=='docker'
 return subprocess.run(['docker','--host',endpoint,*args[1:]],cwd=ROOT,env=docker_env,capture_output=True,text=True,timeout=timeout)
def checked(args,timeout=60):
 result=command(args,timeout)
 if result.returncode:raise RuntimeError('owned fixture command refused')
 return result.stdout
image=checked(['docker','image','inspect','aegis-community/controller:0.1.0-alpha.1','--format','{{.Id}}']).strip()
assert re.fullmatch(r'sha256:[0-9a-f]{64}',image)
controller=json.loads(checked(['docker','inspect','aegis-community-controller-1']))[0]
if controller['Image']!=image or not controller['State']['Running']:raise SystemExit('Running Aegis controller must match the tested packaged image')
mounts=controller['Mounts']
volume=next(m['Name'] for m in mounts if m['Destination']=='/var/lib/aegis' and m['Type']=='volume')
if volume!='aegis-community_controller_data':raise SystemExit('Expected owned local Aegis data volume is required')
count=0
containers=[]
def run(entry,args,extra=(),success=True):
 global count
 count+=1
 name='aegis-snapshot-proof-'+nonce[:16]+'-'+str(count)
 containers.append(name)
 argv=['docker','run','--pull=never','--log-driver','none','--rm','--name',name,'--label','io.aegis.snapshot-proof='+nonce,'--read-only','--network','none','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','512m','--cpus','1','--tmpfs','/tmp:rw,noexec,nosuid,size=128m,uid=10001,gid=10001','--mount','type=volume,src='+volume+',dst=/var/lib/aegis','--env','SQLITE_TMPDIR=/tmp','--env','TMPDIR=/tmp',*extra,'--entrypoint',entry,image,*args]
 result=command(argv,45)
 if result.returncode!=(0 if success else 1):raise RuntimeError('owned packaged fixture phase refused')
 return result

def check(name):checks.append({'id':name,'result':'PASS'});print(name+': PASS',flush=True)
def gateway():
 with opener.open('http://127.0.0.1:8080/catalog?id=42',timeout=5) as response:
  assert response.status==200
  revision=response.headers['X-Aegis-Revision'];mode=response.headers['X-Aegis-Mode']
  assert re.fullmatch(r'sha256:[0-9a-f]{64}',revision) and mode in ('observe','protect')
  return {'policy_digest':revision,'mode':mode}
before=gateway()
with opener.open('http://127.0.0.1:7410/api/v1/health/live',timeout=5) as response:assert response.status==200
check('source_controller_and_gateway_live_before_snapshot')
try:
 run('/bin/mkdir',['-m','700',private])
 result=run('aegisctl',['backup','create',private+'/aegis.db','--json'])
 receipt=json.loads(result.stdout)
 assert receipt['scope']=='controller_database_only' and receipt['status']=='created'
 assert all(receipt[k] is False for k in ('gateway_configuration_captured','tool_manifest_captured','restore_verified'))
 assert 100<=receipt['byte_count']<=536870912 and re.fullmatch(r'sha256:[0-9a-f]{64}',receipt['database_digest'])
 check('packaged_nonroot_network_none_snapshot_created_with_false_restore_flags')
 metadata=run('stat',['-c','%a %u %h %s',private+'/aegis.db']).stdout.split()
 assert metadata[:3]==['600','10001','1'] and int(metadata[3])==receipt['byte_count']
 check('actual_sensitive_snapshot_is_private_single_link_and_bounded')
 first=run('sha256sum',[private+'/aegis.db']).stdout.split()[0]
 assert receipt['database_digest']=='sha256:'+first
 check('packaged_receipt_matches_actual_artifact_hash')
 refusal=run('aegisctl',['backup','create',private+'/aegis.db','--json'],success=False)
 assert not refusal.stdout
 check('packaged_replay_refuses_existing_target')
 # This copies only the completed offline snapshot, never a live DB/WAL.
 # Store.Open may change journal headers, so verify a separate disposable copy.
 run('/bin/mkdir',['-m','700',private+'/validation'])
 run('/bin/cp',['-p',private+'/aegis.db',private+'/validation/aegis.db'])
 audit=run('aegisctl',['audit','verify'],extra=('--env','AEGIS_DATA='+private+'/validation'))
 assert 'Audit chain consistent' in audit.stdout
 check('isolated_offline_validation_copy_passes_actual_audit_chain_verifier')
 final=run('sha256sum',[private+'/aegis.db']).stdout.split()[0]
 assert final==first
 check('offline_validation_does_not_mutate_original_snapshot')
 after=gateway()
 assert after==before
 with opener.open('http://127.0.0.1:7410/api/v1/health/live',timeout=5) as response:assert response.status==200
 check('source_controller_and_gateway_policy_remain_available_and_unchanged')
 remaining=checked(['docker','ps','--all','--filter','label=io.aegis.snapshot-proof='+nonce,'--format','{{.Names}}']).strip()
 assert not remaining
 check('only_owned_completed_proof_containers_used_and_none_remain')
 report={'schema_version':'1.0','status':'PASS','recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'packaged private controller-state snapshot of the existing local Aegis demo; offline audit-copy validation only; no application restore claim','image_digest':image,'fixture_id':nonce,'checks':checks,'receipt':receipt,'file_metadata':{'mode':'0600','uid':10001,'links':1,'byte_count':int(metadata[3])},'gateway_before':before,'gateway_after':after,'application_restore_verified':False}
 evidence=os.environ.get('AEGIS_PACKAGED_SNAPSHOT_EVIDENCE')
 if evidence:pathlib.Path(evidence).write_text(json.dumps(report,indent=2)+'\n')
 print('packaged_snapshot_checks: '+str(len(checks)),flush=True)
except BaseException:
 for name in containers:
  command(['docker','rm','--force',name],15)
 raise
