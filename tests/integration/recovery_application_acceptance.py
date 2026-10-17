#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Opt-in isolated reference-demo recovery drill. Never selects existing app volumes."""
import datetime,hashlib,http.cookiejar,json,os,pathlib,re,secrets,subprocess,tempfile,time,urllib.error,urllib.parse,urllib.request
from recovery_isolation import prepare,validate
ROOT=pathlib.Path(__file__).resolve().parents[2]
if not __debug__ or os.environ.get('AEGIS_RECOVERY_DRILL')!='1':raise SystemExit('Set AEGIS_RECOVERY_DRILL=1 with assertions enabled for an isolated synthetic application drill')
context=os.environ.get('DOCKER_CONTEXT','');endpoint=os.environ.get('DOCKER_HOST','') if not context else ''
if not endpoint:
 context=context or subprocess.check_output(['docker','context','show'],text=True).strip()
 endpoint=subprocess.check_output(['docker','context','inspect',context,'--format','{{.Endpoints.docker.Host}}'],text=True).strip()
u=urllib.parse.urlsplit(endpoint)
if not(u.scheme=='unix' and not u.netloc and not u.query and not u.fragment and pathlib.PurePosixPath(u.path).is_absolute()):raise SystemExit('A local Unix engine is required')
env={k:v for k,v in os.environ.items() if k not in {'DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION','DOCKER_TLS'}}
nonce=secrets.token_hex(12);project='aegis-recovery-'+nonce;archive=project+'-archive';checks=[];receipts=[];objects=[]
def raw(args,timeout=120,success=True):
 result=subprocess.run(['docker','--host',endpoint,*args],cwd=ROOT,env=env,capture_output=True,text=True,timeout=timeout)
 if success and result.returncode:raise RuntimeError('owned recovery drill operation failed')
 return result
image=raw(['image','inspect','aegis-community/controller:0.1.0-alpha.1','--format','{{.Id}}']).stdout.strip()
if not re.fullmatch(r'sha256:[0-9a-f]{64}',image):raise SystemExit('Built recovery image is unavailable')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def check(name):checks.append({'id':name,'result':'PASS'});print(name+': PASS',flush=True)
def cli(entry,args,mounts=(),extra=(),success=True):
 name=project+'-helper-'+str(len(objects));objects.append(name)
 command=['run','--rm','--pull=never','--name',name,'--label','io.aegis.recovery-proof='+nonce,'--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--pids-limit','64','--cpus','1','--log-driver','none','--tmpfs','/tmp:rw,noexec,nosuid,size=128m,uid=10001,gid=10001','--env','SQLITE_TMPDIR=/tmp']
 for volume,target,readonly in mounts:command+=['--mount','type=volume,src='+volume+',dst='+target+(',readonly' if readonly else '')]
 command+=list(extra)+['--entrypoint',entry,image,*args]
 result=raw(command,90,success)
 if not success:assert result.returncode!=0 and not result.stdout
 return result
with tempfile.TemporaryDirectory(prefix='aegis-recovery-drill-') as temporary:
 directory=pathlib.Path(temporary).resolve();spec=json.loads(raw(['compose','-f','deploy/compose.demo.yaml','config','--format','json']).stdout)
 spec=prepare(spec)
 configuration=directory/'compose.json';configuration.write_text(json.dumps(spec))
 prefix=['compose','-p',project,'-f',str(configuration)]
 def compose(*args,success=True):return raw([*prefix,*args],180,success)
 def container(service):return compose('ps','--all','--quiet',service).stdout.strip()
 def inspect(service):return json.loads(raw(['inspect',container(service)]).stdout)[0]
 def port(service,target):
  value=inspect(service)['NetworkSettings']['Ports'][str(target)+'/tcp'];assert len(value)==1 and value[0]['HostIp']=='127.0.0.1';return int(value[0]['HostPort'])
 def wait(base):
  for _ in range(80):
   try:
    with opener.open(base+'/api/v1/health/live',timeout=2) as response:
     if response.status==200:return
   except OSError:pass
   time.sleep(.5)
  raise RuntimeError('isolated restored controller did not become live')
 def request(base,path,body=None,cookie=None,csrf=None,expect=200,idem=None):
  headers={}
  if cookie:headers['Cookie']='aegis_session='+cookie
  if csrf:headers['X-CSRF-Token']=csrf
  if idem:headers['Idempotency-Key']=idem
  if body is not None:headers['Content-Type']='application/json'
  req=urllib.request.Request(base+'/api/v1'+path,data=None if body is None else json.dumps(body).encode(),headers=headers)
  try:
   with opener.open(req,timeout=20) as response:status=response.status;payload=response.read();cookie_header=response.headers.get('Set-Cookie','')
  except urllib.error.HTTPError as error:status=error.code;payload=error.read();cookie_header=''
  assert status==expect,'unexpected isolated API status'
  return json.loads(payload) if payload else {},cookie_header
 def gateway(base):
  with opener.open(base+'/catalog?id=42',timeout=5) as response:
   assert response.status==200
   return {'policy_digest':response.headers['X-Aegis-Revision'],'mode':response.headers['X-Aegis-Mode']}
 namespace_verified=False
 try:
  effective=json.loads(compose('config','--format','json').stdout)
  validate(effective,project,str(ROOT/'alpha/fixtures/scanners'))
  namespace_verified=True
  compose('up','-d','--no-build')
  for attempt in range(40):
   try:
    if inspect('controller')['State']['Running'] and inspect('controller')['NetworkSettings']['Ports'].get('7410/tcp'):break
   except (KeyError,RuntimeError):pass
   time.sleep(.5)
  else:raise RuntimeError('isolated controller did not start')
  controller_base='http://127.0.0.1:'+str(port('controller',7410));gateway_base='http://127.0.0.1:'+str(port('gateway',8080));wait(controller_base)
  # Setup-info deliberately never exposes bootstrap tokens; read only this
  # disposable controller's bootstrap delivery log internally and never emit it.
  logs=compose('logs','--no-color','controller').stdout
  token=None
  for line in logs.splitlines():
   start=line.find('{')
   if start<0:continue
   try:entry=json.loads(line[start:])
   except ValueError:continue
   if entry.get('event')=='local_bootstrap_token':token=entry['token']
  if not token:raise RuntimeError('isolated bootstrap delivery unavailable')
  password=secrets.token_urlsafe(32)
  request(controller_base,'/auth/bootstrap',{'token':token,'password':password})
  login,cookie_header=request(controller_base,'/auth/login',{'password':password});cookie=cookie_header.split('aegis_session=',1)[1].split(';',1)[0];csrf=login['csrf_token']
  policy_before=gateway(gateway_base)
  repository,_=request(controller_base,'/repos',{'app_id':'app_demo','asset_id':'safe','acknowledge_read_only':True},cookie=cookie,csrf=csrf,expect=201)
  repositories,_=request(controller_base,'/repos',cookie=cookie)
  scan,_=request(controller_base,'/scans',{'schema_version':'1.0','app_id':'app_demo','repository_id':repository['repository_id'],'map_digest':repository['map_digest'],'mode':'repo_offline','tool_ids':['bandit'],'tool_timeout_seconds':30},cookie=cookie,csrf=csrf,expect=202,idem=secrets.token_hex(16))
  check('fresh_isolated_demo_and_owner_session_created')
  source=inspect('controller');data_volume=next(x['Name'] for x in source['Mounts'] if x['Destination']=='/var/lib/aegis');policy_volume=next(x['Name'] for x in inspect('gateway')['Mounts'] if x['Destination']=='/var/lib/deployer')
  if not data_volume.startswith(project+'_') or not policy_volume.startswith(project+'_'):raise RuntimeError('drill volume ownership mismatch')
  raw(['volume','create','--label','io.aegis.recovery-proof='+nonce,archive])
  common=[(archive,'/var/lib/aegis',False)]
  mounts=[*common,(data_volume,'/source',True),(policy_volume,'/source-policy',True)]
  created=json.loads(cli('aegisctl',['backup','bundle','/var/lib/aegis/bundle','--json'],mounts,('--env','AEGIS_DATA=/source','--env','GATEWAY_POLICY_ROOT=/source-policy')).stdout);receipts.append(created)
  assert created['policy_digest']==policy_before['policy_digest'] and gateway(gateway_base)==policy_before
  check('bundle_captured_while_matching_gateway_continues_serving')
  compose('stop','controller');compose('rm','--force','controller','init')
  assert gateway(gateway_base)==policy_before
  volume_meta=json.loads(raw(['volume','inspect',data_volume]).stdout)[0]
  if volume_meta.get('Labels',{}).get('com.docker.compose.project')!=project:raise RuntimeError('database destruction requires an owned disposable volume')
  raw(['volume','rm',data_volume])
  check('only_disposable_database_fixture_destroyed_with_gateway_lkg_available')
  restored=json.loads(cli('aegisctl',['backup','restore','/var/lib/aegis/bundle','/var/lib/aegis/restored','--confirm',created['bundle_digest'],'--json'],common).stdout);receipts.append(restored)
  assert restored['restored_authorities_invalidated'] is True and restored['scanner_cleanup_holds_preserved'] is True and restored['live_activated'] is False
  compose('create','--no-build','init')
  target=[*common,(data_volume,'/target',False)]
  cli('/bin/cp',['-p','/var/lib/aegis/restored/data/aegis.db','/target/aegis.db'],target)
  cli('/bin/cp',['-p','/var/lib/aegis/restored/data/.restore-complete.json','/target/.restore-complete.json'],target)
  assert gateway(gateway_base)==policy_before
  compose('up','-d','--no-deps','--no-build','init','controller')
  controller_base='http://127.0.0.1:'+str(port('controller',7410));wait(controller_base)
  request(controller_base,'/auth/session',cookie=cookie,expect=401)
  new_login,new_header=request(controller_base,'/auth/login',{'password':password});new_cookie=new_header.split('aegis_session=',1)[1].split(';',1)[0]
  request(controller_base,'/auth/session',cookie=new_cookie)
  check('restored_controller_denies_prebackup_session_and_allows_fresh_owner_login')
  after_repositories,_=request(controller_base,'/repos',cookie=new_cookie);assert after_repositories==repositories
  status,_=request(controller_base,'/scans/'+scan['job_id'],cookie=new_cookie)
  assert status['job']['job_id']==scan['job_id'] and status['job']['state']=='cancelled'
  assert gateway(gateway_base)==policy_before
  check('restored_inventory_links_and_gateway_revision_match_snapshot')
  verified=json.loads(cli('aegisctl',['backup','verify','/var/lib/aegis/bundle','--json'],common).stdout);assert verified['bundle_digest']==created['bundle_digest'];receipts.append(verified)
  check('original_bundle_remains_immutable_and_verifiable_after_application_recovery')
  report={'schema_version':'1.0','status':'PASS','scope':'isolated synthetic demo database-destruction and application recovery drill; no production or independent-install claim','recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':checks,'receipts':receipts,'gateway_before':policy_before,'gateway_after':gateway(gateway_base),'image_digest':image,'application_restore_observed':True}
  evidence=os.environ.get('AEGIS_RECOVERY_DRILL_EVIDENCE')
  if evidence:pathlib.Path(evidence).write_text(json.dumps(report,indent=2)+'\n')
  print('application_recovery_checks: '+str(len(checks)),flush=True)
 finally:
  if namespace_verified:compose('down','--volumes','--remove-orphans',success=False)
  for name in objects:raw(['rm','--force',name],30,False)
  raw(['volume','rm',archive],30,False)
