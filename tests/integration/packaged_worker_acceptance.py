#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Explicit isolated worker execution. No retained demo resources are selected."""
import datetime,json,os,pathlib,re,secrets,subprocess,tempfile,time,urllib.error,urllib.request
from recovery_isolation import prepare,validate
from engine_authz_acceptance import PrivateOperationTimeout
ROOT=pathlib.Path(__file__).resolve().parents[2]
if not __debug__ or os.environ.get('AEGIS_PACKAGED_WORKER_TEST')!='1':raise SystemExit('Set AEGIS_PACKAGED_WORKER_TEST=1 with assertions enabled')
context=os.environ.get('DOCKER_CONTEXT','');endpoint=os.environ.get('DOCKER_HOST','') if not context else ''
if not endpoint:
 context=context or subprocess.check_output(['docker','context','show'],text=True).strip();endpoint=subprocess.check_output(['docker','context','inspect',context,'--format','{{.Endpoints.docker.Host}}'],text=True).strip()
if not re.fullmatch(r'unix:///[^\r\n?#]+',endpoint):raise SystemExit('Explicit local Unix engine required')
env={k:v for k,v in os.environ.items() if k not in {'DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION','DOCKER_TLS'}}
nonce=secrets.token_hex(12);project='aegis-worker-'+nonce;secret_volume=project+'-credential';helpers=[];checks=[];namespace_verified=False;started=False;confirmed=False;worker_name=project+'-runner';work_root=None;evidence=None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def raw(args,timeout=120,success=True):
 try:result=subprocess.run(['docker','--host',endpoint,*args],cwd=ROOT,env=env,capture_output=True,text=True,timeout=timeout)
 except subprocess.TimeoutExpired as error:raise PrivateOperationTimeout(error.cmd,error.timeout,output=error.output,stderr=error.stderr) from None
 if success and result.returncode:raise RuntimeError('Owned packaged worker operation failed')
 return result
broker_mode=os.environ.get('AEGIS_PACKAGED_BROKER_TEST')=='1';broker=None
authz_mode=os.environ.get('AEGIS_PACKAGED_ENGINE_AUTHZ_TEST')=='1';authz_engine=None
controller_gate_mode=os.environ.get('AEGIS_PACKAGED_CONTROLLER_GATE_TEST')=='1'
admission_mode=os.environ.get('AEGIS_PACKAGED_ADMISSION_TEST')=='1'
reconcile_mode=os.environ.get('AEGIS_PACKAGED_RECONCILE_TEST')=='1';reconciler_volume=None
if reconcile_mode and not admission_mode:raise SystemExit('Independent reconciliation requires the explicit native admission fixture')
if admission_mode and not (controller_gate_mode and authz_mode and broker_mode):raise SystemExit('Native admission fixture requires all explicit broker/controller/engine guards')
if controller_gate_mode and not authz_mode:raise SystemExit('Controller gate fixture requires the explicit restricted TLS fixture')
if authz_mode:
 from packaged_engine_fixture import require_ci
 require_ci()
 if os.environ.get('AEGIS_WORKER_TEST_ALL_TOOLS')=='1':raise SystemExit('The isolated engine fixture preloads only Bandit')
image=raw(['image','inspect','aegis-community/scanner-worker:0.1.0-alpha.1','--format','{{.Id}}']).stdout.strip()
if not re.fullmatch(r'sha256:[0-9a-f]{64}',image):raise SystemExit('Build the pinned worker image first')
engine_socket=os.environ.get('AEGIS_WORKER_TEST_ENGINE_SOCKET','/var/run/docker.sock')
if not pathlib.PurePosixPath(engine_socket).is_absolute() or any(c in engine_socket for c in ',:\r\n'):raise SystemExit('Canonical daemon-host Unix socket path required')
def check(name):checks.append({'id':name,'result':'PASS'});print(name+': PASS',flush=True)
def helper(args,mounts=(),entry='aegis-research',user='10001:10001',caps=(),extra=(),success=True):
 name=project+'-helper-'+str(len(helpers));helpers.append(name)
 command=['run','--rm','--pull=never','--name',name,'--label','io.aegis.worker-proof='+nonce,'--network','none','--read-only','--user',user,'--cap-drop','ALL','--security-opt','no-new-privileges','--memory','192m','--pids-limit','64','--log-driver','none']
 for cap in caps:command+=['--cap-add',cap]
 for mount in mounts:command+=['--mount',mount]
 if authz_engine is not None and entry=='aegis-research':command+=['--mount','type=bind,src='+str(authz_engine.client_dir)+',dst=/run/engine-tls,readonly','--env','AEGIS_SCANNER_ENGINE_TLS_DIR=/run/engine-tls']
 return raw(command+list(extra)+['--entrypoint',entry,image,*args],90,success)
with tempfile.TemporaryDirectory(prefix='aegis-worker-config-') as temporary:
 directory=pathlib.Path(temporary).resolve();spec=prepare(json.loads(raw(['compose','-f','deploy/compose.demo.yaml','config','--format','json']).stdout));configuration=directory/'compose.json';configuration.write_text(json.dumps(spec));prefix=['compose','-p',project,'-f',str(configuration)]
 def compose(*args,success=True):return raw([*prefix,*args],180,success)
 def inspect(service):return json.loads(raw(['inspect',compose('ps','--all','--quiet',service).stdout.strip()]).stdout)[0]
 def request(base,path,body=None,cookie=None,csrf=None,expect=200,key=None):
  headers={}
  if cookie:headers['Cookie']=cookie
  if csrf:headers['X-CSRF-Token']=csrf
  if body is not None:headers['Content-Type']='application/json'
  if key:headers['Idempotency-Key']=key
  req=urllib.request.Request(base+'/api/v1'+path,data=None if body is None else json.dumps(body).encode(),headers=headers)
  try:
   with opener.open(req,timeout=20) as response:status=response.status;payload=response.read(131073);session=response.headers.get('Set-Cookie','').split(';')[0]
  except urllib.error.HTTPError as error:status=error.code;payload=error.read(131073);session=''
  if status!=expect or len(payload)>131072:raise RuntimeError('Unexpected owned worker-fixture API response')
  return json.loads(payload) if payload else {},session
 try:
  validate(json.loads(compose('config','--format','json').stdout),project,str(ROOT/'alpha/fixtures/scanners'));namespace_verified=True
  no_cli=helper(['which','docker'],entry='/bin/busybox',success=False);assert no_cli.returncode==1 and not no_cli.stdout
  work_root=pathlib.Path(tempfile.mkdtemp(prefix='aegis-worker-runtime-',dir='/tmp' if authz_mode else None)).resolve();assert work_root.name.startswith('aegis-worker-runtime-') and work_root.parent==pathlib.Path('/tmp' if authz_mode else tempfile.gettempdir()).resolve()
  root_mount='type=bind,src='+str(work_root)+',dst='+str(work_root)
  helper(['chown','10001:10001','/target'],entry='/bin/busybox',user='0:0',caps=['CHOWN'],mounts=['type=bind,src='+str(work_root)+',dst=/target'])
  if authz_mode:
   from packaged_engine_fixture import EngineFixture
   authz_engine=EngineFixture(work_root);engine_socket=authz_engine.socket
  group=helper(['stat','-c','%g','/run/engine/docker.sock'],entry='/bin/busybox',mounts=['type=bind,src='+engine_socket+',dst=/run/engine/docker.sock,readonly']).stdout.strip();assert group.isdecimal() and int(group)<2**31
  preflight=json.loads(helper(['engine-preflight','bandit','/opt/aegis'],mounts=['type=bind,src='+engine_socket+',dst=/run/engine/docker.sock,readonly'],extra=['--group-add',group]).stdout);assert preflight['engine_writes_performed'] is False and preflight['cleanup_release_authorized'] is False
  check('pinned_nonroot_package_has_no_docker_cli_and_reads_sdk_metadata')
  compose('up','-d','--no-build')
  for _ in range(80):
   try:
    controller=inspect('controller');ports=controller['NetworkSettings']['Ports'].get('7410/tcp');assert ports and ports[0]['HostIp']=='127.0.0.1';base='http://127.0.0.1:'+ports[0]['HostPort'];request(base,'/health/live');break
   except (OSError,RuntimeError,AssertionError,KeyError):time.sleep(.5)
  else:raise RuntimeError('Owned worker fixture did not start')
  logs=compose('logs','--no-color','controller').stdout;token=None
  for line in logs.splitlines():
   start=line.find('{')
   if start<0:continue
   try:item=json.loads(line[start:])
   except ValueError:continue
   if item.get('event')=='local_bootstrap_token':token=item['token']
  if not token:raise RuntimeError('Owned bootstrap delivery unavailable')
  password=secrets.token_urlsafe(32);request(base,'/auth/bootstrap',{'token':token,'password':password});login,cookie=request(base,'/auth/login',{'password':password});csrf=login['csrf_token']
  repo,_=request(base,'/repos',{'app_id':'app_demo','asset_id':'vulnerable','acknowledge_read_only':True},cookie,csrf,201);owner=repo['owner_id']
  tools=['bandit','gitleaks','osv_v2','semgrep_ce','syft','trivy'] if os.environ.get('AEGIS_WORKER_TEST_ALL_TOOLS')=='1' else ['bandit']
  request_body={'schema_version':'1.0','app_id':'app_demo','repository_id':repo['repository_id'],'map_digest':repo['map_digest'],'mode':'repo_offline','tool_ids':tools,'tool_timeout_seconds':30}
  job,_=request(base,'/scans',request_body,cookie,csrf,202,key=secrets.token_hex(16))
  socket_volume=next(m['Name'] for m in controller['Mounts'] if m['Destination']=='/run/scanner');assert socket_volume.startswith(project+'_')
  socket_meta=json.loads(raw(['volume','inspect',socket_volume]).stdout)[0];assert socket_meta.get('Labels',{}).get('com.docker.compose.project')==project
  raw(['volume','create','--label','io.aegis.worker-proof='+nonce,secret_volume])
  worker_id='packaged-'+nonce
  compose('run','--rm','--no-deps','--volume',secret_volume+':/run/scanner','--entrypoint','aegisctl','init','scanner-worker','enroll',worker_id,'10','/run/scanner/worker.credential')
  check('isolated_owner_queue_and_private_uid_socket_enrollment_created')
  mounts=[root_mount,'type=bind,src='+str(ROOT/'alpha/fixtures/scanners')+',dst=/opt/aegis/repositories,readonly','type=bind,src='+engine_socket+',dst=/run/engine/docker.sock,readonly','type=volume,src='+socket_volume+',dst=/run/scanner,readonly','type=volume,src='+secret_volume+',dst=/run/worker-credential,readonly']
  arguments=['worker-once-bound','/run/scanner/worker.sock','/run/worker-credential/worker.credential',owner,'/opt/aegis','/opt/aegis/repositories',str(work_root/'engine-journal')]
  started=True;confirmed=False
  missing=helper(arguments,mounts=mounts,extra=['--group-add',group,'--env','TMPDIR='+str(work_root)],success=False)
  missing_report=json.loads(missing.stdout);assert missing.returncode!=0 and missing_report['state']=='not_claimed' and not missing_report['receipts']
  still_queued,_=request(base,'/scans/'+job['job_id'],cookie=cookie);assert still_queued['job']['state']=='queued'
  confirmed=True;check('bound_worker_refuses_missing_operator_binding_without_claiming')
  provisioning=json.loads(helper(['engine-binding-input',str(work_root/'aegis-scanner-workspaces-10001')],mounts=[root_mount,'type=bind,src='+engine_socket+',dst=/run/engine/docker.sock,readonly'],extra=['--group-add',group]).stdout)
  assert provisioning['engine_digest']==preflight['engine_digest'] and provisioning['controller_binding_verified'] is False and provisioning['cleanup_release_authorized'] is False
  binding=json.loads(compose('exec','-T','controller','aegisctl','scanner-engine','bind',provisioning['engine_digest'],provisioning['registry_digest']).stdout)
  assert binding['document']['owner_id']==owner and binding['document']['engine_digest']==preflight['engine_digest']
  replay=json.loads(compose('exec','-T','controller','aegisctl','scanner-engine','bind',provisioning['engine_digest'],provisioning['registry_digest']).stdout);assert replay==binding
  assert compose('exec','-T','controller','aegisctl','scanner-engine','bind','sha256:'+'0'*64,provisioning['registry_digest'],success=False).returncode!=0
  helper(['mkdir','-m','700',str(work_root/'different')],entry='/bin/busybox',mounts=[root_mount])
  confirmed=False
  different=helper(arguments,mounts=mounts,extra=['--group-add',group,'--env','TMPDIR='+str(work_root/'different')],success=False)
  different_report=json.loads(different.stdout);assert different.returncode!=0 and different_report['state']=='not_claimed' and not different_report['receipts']
  still_queued,_=request(base,'/scans/'+job['job_id'],cookie=cookie);assert still_queued['job']['state']=='queued'
  assert helper(['test','-e',str(work_root/'engine-journal')],entry='/bin/busybox',mounts=[root_mount],success=False).returncode==1
  confirmed=True;check('operator_binding_is_immutable_and_changed_registry_refuses_before_claim')
  confirmed=False
  missing_journal=helper(arguments,mounts=mounts,extra=['--group-add',group,'--env','TMPDIR='+str(work_root)],success=False)
  missing_journal_report=json.loads(missing_journal.stdout);assert missing_journal.returncode!=0 and missing_journal_report['state']=='not_claimed' and not missing_journal_report['receipts']
  still_queued,_=request(base,'/scans/'+job['job_id'],cookie=cookie);assert still_queued['job']['state']=='queued'
  confirmed=True;check('bound_worker_refuses_missing_journal_provisioning_before_claim')
  journal_mounts=[root_mount,'type=bind,src='+engine_socket+',dst=/run/engine/docker.sock,readonly']
  partial=work_root/'partial-empty-journal';helper(['mkdir','-m','700',str(partial)],entry='/bin/busybox',mounts=[root_mount])
  partial_init=helper(['engine-journal-init',str(partial)],mounts=journal_mounts,extra=['--group-add',group],success=False);assert partial_init.returncode!=0
  assert not helper(['ls','-A',str(partial)],entry='/bin/busybox',mounts=[root_mount]).stdout.strip()
  check('existing_partial_journal_is_refused_without_creating_lock_or_identity')
  journal_input=json.loads(helper(['engine-journal-init',str(work_root/'engine-journal')],mounts=journal_mounts,extra=['--group-add',group]).stdout)
  assert journal_input['engine_digest']==preflight['engine_digest'] and journal_input['controller_binding_verified'] is False and journal_input['cleanup_release_authorized'] is False
  assert json.loads(helper(['engine-journal-init',str(work_root/'engine-journal')],mounts=journal_mounts,extra=['--group-add',group]).stdout)==journal_input
  journal_binding=json.loads(compose('exec','-T','controller','aegisctl','scanner-engine','bind-journal',journal_input['journal_root_digest'],journal_input['journal_namespace_digest']).stdout)
  assert journal_binding['document']['engine_binding_digest']==binding['binding_digest'] and journal_binding['document']['journal_namespace_digest']==journal_input['journal_namespace_digest']
  assert json.loads(compose('exec','-T','controller','aegisctl','scanner-engine','bind-journal',journal_input['journal_root_digest'],journal_input['journal_namespace_digest']).stdout)==journal_binding
  assert compose('exec','-T','controller','aegisctl','scanner-engine','bind-journal',journal_input['journal_root_digest'],'sha256:'+'0'*64,success=False).returncode!=0
  # Only empty, never-attempted nonce-owned test directories are moved here.
  # This exercises substitution; there is no operator namespace reset command.
  helper(['mv',str(work_root/'engine-journal'),str(work_root/'approved-empty-journal')],entry='/bin/busybox',mounts=[root_mount])
  fresh=json.loads(helper(['engine-journal-init',str(work_root/'engine-journal')],mounts=journal_mounts,extra=['--group-add',group]).stdout);assert fresh['journal_root_digest']==journal_input['journal_root_digest'] and fresh['journal_namespace_digest']!=journal_input['journal_namespace_digest']
  confirmed=False
  substituted=helper(arguments,mounts=mounts,extra=['--group-add',group,'--env','TMPDIR='+str(work_root)],success=False)
  substituted_report=json.loads(substituted.stdout);assert substituted.returncode!=0 and substituted_report['state']=='not_claimed' and not substituted_report['receipts']
  still_queued,_=request(base,'/scans/'+job['job_id'],cookie=cookie);assert still_queued['job']['state']=='queued'
  empty=json.loads(helper(['engine-journal-status',str(work_root/'engine-journal'),preflight['engine_digest']],mounts=[root_mount]).stdout);assert empty['attempts']==0
  confirmed=True
  helper(['mv',str(work_root/'engine-journal'),str(work_root/'substituted-empty-journal')],entry='/bin/busybox',mounts=[root_mount])
  helper(['mv',str(work_root/'approved-empty-journal'),str(work_root/'engine-journal')],entry='/bin/busybox',mounts=[root_mount])
  check('immutable_journal_binding_refuses_a_fresh_namespace_at_the_approved_path')
  profile_env={**env,'AEGIS_SCANNER_ENGINE_GID':group,'AEGIS_SCANNER_WORK_ROOT':str(work_root),'AEGIS_SCANNER_ASSET_ROOT':str(ROOT/'alpha/fixtures/scanners'),'AEGIS_SCANNER_ENGINE_SOCKET':engine_socket,'AEGIS_SCANNER_OWNER':owner}
  resolved=subprocess.run(['docker','--host',endpoint,'compose','-p',project,'-f',str(ROOT/'deploy/compose.demo.yaml'),'-f',str(ROOT/'deploy/compose.scanner-worker.yaml'),'--profile','operator-scanner','config','--format','json'],env=profile_env,cwd=ROOT,capture_output=True,text=True,timeout=30)
  assert resolved.returncode==0
  profile=json.loads(resolved.stdout)['services']['scanner-worker']
  assert profile['user']=='10001:10001' and profile['read_only'] and profile['network_mode']=='none' and profile['cap_drop']==['ALL'] and not profile.get('privileged') and profile['restart']=='no' and profile['profiles']==['operator-scanner']
  assert profile['command'][0]=='worker-once-bound' and profile['command'][3]==owner and profile['environment']['TMPDIR']==str(work_root)
  assert all(m.get('read_only') for m in profile['volumes'] if m['target']!=str(work_root))
  assert any(m['type']=='bind' and m['source']==str(work_root) and m['target']==str(work_root) for m in profile['volumes'])
  check('explicit_compose_worker_profile_matches_private_mount_and_hardening_contract')
  if authz_engine is not None:
   confirmed=False
   invalid_tls=helper(arguments,mounts=mounts,extra=['--env','TMPDIR='+str(work_root),'--env','AEGIS_SCANNER_ENGINE_TLS_DIR=/run/missing-tls'],success=False)
   invalid_report=json.loads(invalid_tls.stdout);assert invalid_tls.returncode!=0 and invalid_report['state']=='not_claimed' and not invalid_report['receipts']
   queued,_=request(base,'/scans/'+job['job_id'],cookie=cookie);assert queued['job']['state']=='queued'
   confirmed=True;check('invalid_tls_identity_refuses_before_claim_without_plaintext_fallback')
  if broker_mode:
   from broker_fixture import BrokerFixture
   confirmed=False
   broker=BrokerFixture(raw,compose,helper,check,helpers,project,nonce,worker_id,owner,group,mounts,root_mount,work_root,secret_volume,arguments,engine_fixture=authz_engine)
   queued,_=request(base,'/scans/'+job['job_id'],cookie=cookie);assert queued['job']['state']=='queued'
   confirmed=True
   if controller_gate_mode:
    confirmed=False;started=True
    authz_engine.bind_controller(raw,compose,project,nonce,owner,socket_volume,provisioning,worker_id)
    check('separate_packaged_authorizer_has_only_selected_admission_channel_and_readonly_source' if admission_mode else 'separate_packaged_authorizer_has_only_private_observer_channel_and_readonly_source')
    check('native_tls_engine_refuses_unregistered_profile_without_allocation')
    confirmed=True
   broker.create_client(worker_name)
   broker_env={**profile_env,'AEGIS_SCANNER_BROKER_ID':worker_id}
   broker_file='deploy/compose.scanner-broker.yaml';broker_profile_name='operator-broker'
   if authz_engine is not None:
    broker_file='deploy/compose.scanner-broker-tls.yaml';broker_profile_name='operator-broker-tls';broker_env['AEGIS_SCANNER_ENGINE_TLS_ROOT']=str(authz_engine.client_dir)
   broker_profile=subprocess.run(['docker','--host',endpoint,'compose','-p',project,'-f',str(ROOT/'deploy/compose.demo.yaml'),'-f',str(ROOT/broker_file),'--profile',broker_profile_name,'config','--format','json'],env=broker_env,cwd=ROOT,capture_output=True,text=True,timeout=30);assert broker_profile.returncode==0;broker.assert_compose(json.loads(broker_profile.stdout))
   confirmed=False;started=True;result=raw(['start','--attach',worker_name],120,False)
   state=json.loads(raw(['inspect',worker_name]).stdout)[0]['State'];expected_exit=1 if len(tools)>1 else 0;assert not state['Running'] and state['ExitCode']==expected_exit and result.returncode==expected_exit
   dispatch_outcome=json.loads(result.stdout);assert dispatch_outcome['job_id']==job['job_id'] and dispatch_outcome['receipt_count']==len(tools) and dispatch_outcome['state']==('tool_error' if len(tools)>1 else 'completed')
  else:
   command=['create','--pull=never','--name',worker_name,'--label','io.aegis.worker-proof='+nonce,'--network','none','--read-only','--user','10001:10001','--group-add',group,'--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--pids-limit','128','--cpus','1','--log-driver','none','--env','TMPDIR='+str(work_root),'--env','DOCKER_API_VERSION=0.1','--tmpfs','/tmp:rw,noexec,nosuid,size=32m,uid=10001,gid=10001']
   for mount in mounts:command+=['--mount',mount]
   arguments=['worker-once-bound','/run/scanner/worker.sock','/run/worker-credential/worker.credential',owner,'/opt/aegis','/opt/aegis/repositories',str(work_root/'engine-journal')]
   raw(command+[image,*arguments]);worker=json.loads(raw(['inspect',worker_name]).stdout)[0];host=worker['HostConfig'];assert worker['Config']['User']=='10001:10001' and host['ReadonlyRootfs'] and host['NetworkMode']=='none' and host['CapDrop']==['ALL'] and not host['Privileged'] and host['RestartPolicy']['Name']=='no'
   assert not any(m['Destination']=='/var/lib/aegis' for m in worker['Mounts']);check('worker_profile_has_no_controller_database_or_network_and_is_hardened')
   confirmed=False;started=True;result=raw(['start','--attach',worker_name],120,False)
   state=json.loads(raw(['inspect',worker_name]).stdout)[0]['State'];expected_exit=1 if len(tools)>1 else 0;assert not state['Running'] and state['ExitCode']==expected_exit and result.returncode==expected_exit,'Packaged worker did not complete its authorized static fixture'
   report=json.loads(result.stdout);assert report['job_id']==job['job_id'] and report['state']==('tool_error' if len(tools)>1 else 'completed') and len(report['receipts'])==len(tools)
  suite,_=request(base,'/scans/'+job['job_id']+'/result',cookie=cookie)
  if broker_mode:assert suite['result_digest']==dispatch_outcome['result_digest']
  else:assert suite==report['result']
  assert suite['document']['evidence_tier']=='T0' and suite['document']['cleanup_required'] is True
  assert suite['document']['finding_claims']>0 and suite['document']['has_tool_error'] is (len(tools)>1)
  check('packaged_worker_commits_actual_guarded_tool_receipts_and_result')
  catalogue,_=request(base,'/findings/catalogue?limit=20',cookie=cookie);assert catalogue['retained_result_count']==1 and catalogue['result']['result_digest']==suite['result_digest'] and len(catalogue['findings']['items'])>0
  for item in catalogue['findings']['items']:assert item['finding']['evidence_tier']=='T0' and item['finding']['status']=='suspected'
  check('packaged_result_reaches_owned_catalogue_without_proof_promotion')
  export_directory='/var/lib/aegis/worker-export-'+nonce;compose('exec','-T','controller','mkdir','-m','700',export_directory)
  plans=[];launch_records=[]
  for tool in tools:
   launch_file=export_directory+'/'+tool+'.json';compose('exec','-T','controller','aegisctl','scanner-launch','export',job['job_id'],tool,launch_file)
   launch=json.loads(compose('exec','-T','controller','cat',launch_file).stdout);plan=launch['document']['plan'];assert launch['document']['schema_version']=='1.2' and plan['engine_journal_binding_digest']==journal_binding['journal_binding_digest'] and plan['engine_journal_namespace_digest']==journal_input['journal_namespace_digest'];assert re.fullmatch(r'aegis-scan-[0-9a-f]{32}',plan['container_id'])
   if authz_engine is not None:authz_engine.assert_absent(plan['container_id'])
   else:assert not raw(['ps','--all','--filter','name=^/'+plan['container_id']+'$','--format','{{.Names}}']).stdout.strip()
   plans.append(plan);launch_records.append(launch)
  plan=plans[0]
  journal=json.loads(helper(['engine-journal-status',str(work_root/'engine-journal'),plan['engine_digest']],mounts=[root_mount]).stdout)
  assert journal['namespace_digest']==journal_input['journal_namespace_digest'] and journal['attempts']==len(tools) and journal['unfinished_attempts']==0 and journal['unresolved_requests']==0 and journal['cleanup_release_authorized'] is False
  confirmed=True;check('exact_child_absence_and_settled_journal_remain_non_authoritative')
  if admission_mode:
   confirmed=False
   snapshot_path=export_directory+'/admission-ledger.db'
   compose('exec','-T','controller','aegisctl','backup','create',snapshot_path,'--json')
   private_snapshot=directory/'admission-ledger.db'
   controller_id=compose('ps','--all','--quiet','controller').stdout.strip()
   raw(['cp',controller_id+':'+snapshot_path,str(private_snapshot)])
   private_snapshot.chmod(0o600)
   authz_engine.bound.verify_ledger(private_snapshot,job['job_id'],launch_records)
   private_snapshot.unlink();compose('exec','-T','controller','rm','--',snapshot_path)
   confirmed=True
   check('actual_native_create_start_remove_have_matching_durable_controller_and_plugin_records')
   check('terminal_generation_is_closed_without_freeing_dispatch')

  initialized_again=helper(['engine-journal-init',str(work_root/'engine-journal')],mounts=journal_mounts,extra=['--group-add',group],success=False);assert initialized_again.returncode!=0
  assert json.loads(helper(['engine-journal-status',str(work_root/'engine-journal'),plan['engine_digest']],mounts=[root_mount]).stdout)==journal
  check('used_bound_journal_cannot_be_reinitialized_or_reset')
  second,_=request(base,'/scans',request_body,cookie,csrf,202,key=secrets.token_hex(16))
  confirmed=False
  if broker_mode:blocked=raw(['start','--attach',worker_name],120,False)
  else:blocked=helper(arguments,mounts=mounts,extra=['--group-add',group,'--env','TMPDIR='+str(work_root)],success=False)
  assert blocked.returncode!=0
  blocked_report=json.loads(blocked.stdout);assert blocked_report['state']=='not_claimed' and (blocked_report['receipt_count']==0 if broker_mode else not blocked_report['receipts'])
  status,_=request(base,'/scans/'+job['job_id'],cookie=cookie);next_status,_=request(base,'/scans/'+second['job_id'],cookie=cookie);assert status['execution_admission']=='cleanup_required' and next_status['job']['state']=='queued'
  after=json.loads(helper(['engine-journal-status',str(work_root/'engine-journal'),plan['engine_digest']],mounts=[root_mount]).stdout);assert after==journal
  confirmed=True
  check('second_job_remains_queued_behind_independent_cleanup_hold')
  if reconcile_mode:
   from packaged_authorizer_fixture import provision_reconciler
   confirmed=False
   reconciler_volume,config_path,reconcile_mounts=provision_reconciler(authz_engine,authz_engine.bound,raw,compose,nonce,socket_volume,project)
   released=json.loads(helper(['reconcile-cleanup',config_path,job['job_id'],authz_engine.bound.generation],mounts=reconcile_mounts,extra=['--group-add',group]).stdout)
   assert released['dispatch_released'] is True and released['request']['job_id']==job['job_id'] and released['request']['generation_id']==authz_engine.bound.generation and len(released['request']['absent'])==1 and released['request']['absent'][0]['container']==plan['container_id']
   # A released generation has no held context left to snapshot; repeating the
   # command must fail closed (controller replay is covered by queue tests).
   assert helper(['reconcile-cleanup',config_path,job['job_id'],authz_engine.bound.generation],mounts=reconcile_mounts,extra=['--group-add',group],success=False).returncode!=0
   status,_=request(base,'/scans/'+job['job_id'],cookie=cookie);assert status['execution_admission']!='cleanup_required'
   confirmed=True;check('independent_reconciler_observes_absence_under_registry_barrier_and_releases_once')
   confirmed=False;started=True;result=raw(['start','--attach',worker_name],120,False)
   assert result.returncode==0
   second_outcome=json.loads(result.stdout);assert second_outcome['job_id']==second['job_id'] and second_outcome['state']=='completed' and second_outcome['receipt_count']==len(tools)
   second_suite,_=request(base,'/scans/'+second['job_id']+'/result',cookie=cookie);assert second_suite['result_digest']==second_outcome['result_digest'] and second_suite['document']['cleanup_required'] is True
   status,_=request(base,'/scans/'+second['job_id'],cookie=cookie);assert status['execution_admission']=='cleanup_required'
   confirmed=True;check('second_sequential_scan_completes_after_release_and_is_held_again')
  engine_proof=None
  if authz_engine is not None:
   confirmed=False;engine_proof=authz_engine.finish();confirmed=True
   check('separate_restricted_engine_and_plugin_journal_settle_without_cleanup_release')
   if controller_gate_mode:check('admitted_authorizer_executes_real_scanner_and_fails_closed_on_loss_and_downgrade' if admission_mode else 'bound_authorizer_executes_real_scanner_and_fails_closed_on_loss_and_downgrade')
  evidence={'schema_version':'1.0','status':'PASS','scope':'Isolated packaged nonroot bound worker executes a real static fixture only after immutable operator engine/registry provisioning; no independent cleanup release or production broker claim','recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':checks,'worker_image':image,'preflight':preflight,'operator_provisioning_input':provisioning,'operator_binding':binding,'journal_provisioning_input':journal_input,'journal_binding':journal_binding,'bound_launch_example':launch,'result':suite,'tool_ids':tools,'catalogue':catalogue,'journal':journal,'container_hardening_verified':True,'child_absence_observed':True,'controller_cleanup_admission':'RELEASED_ONCE_THEN_HELD' if reconcile_mode else 'HELD','sequential_scans':2 if reconcile_mode else 1,'all_engine_writes_mediated':False,'independent_security_signoff':False}
  if engine_proof is not None:evidence['restricted_engine']=engine_proof
  if admission_mode:evidence['actual_controller_mutation_ledger_verified']=authz_engine.bound.ledger_verified
  if broker_mode:
   evidence.update(broker.proof(dispatch_outcome));evidence['scope']='Dedicated fixed scanner broker and minimal socket-only dispatch client; controller-selected worker identity; no production all-write mediation or independent cleanup claim'
 finally:
  if authz_engine is not None:authz_engine.close()
  if not started or confirmed:
   raw(['rm','--force',worker_name],success=False)
   for name in helpers:raw(['rm','--force',name],success=False)
   # Even a stopped standalone authorizer retains the Compose socket volume.
   # After confirmed engine settlement, remove this exact nonce-owned holder
   # before Compose removes its volumes. Unknown work takes the retain branch.
   if authz_engine is not None and authz_engine.bound is not None:authz_engine.bound.cleanup()
   if reconciler_volume is not None:raw(['volume','rm',reconciler_volume],success=False)
   if namespace_verified:compose('down','--volumes','--remove-orphans',success=False)
   raw(['volume','rm',secret_volume],success=False)
   if broker is not None:broker.cleanup_volumes()
   if work_root is not None:
    helper(['chown','-R',str(os.geteuid())+':'+str(os.getegid()),'/target'],entry='/bin/busybox',user='0:0',caps=['CHOWN','DAC_OVERRIDE'],mounts=['type=bind,src='+str(work_root)+',dst=/target'])
    import shutil
    shutil.rmtree(work_root)
  else:
   # Unknown daemon work must retain its records and private mount contents.
   raw(['stop','--time','10',worker_name],30,False)
   if broker_mode:raw(['stop','--time','25',project+'-broker'],40,False)
   print('Unconfirmed fixture retained privately for trusted recovery; no dispatch release performed',flush=True)
  if authz_engine is not None:authz_engine.close()

if evidence is not None:
 assert not raw(['ps','--all','--filter','label=com.docker.compose.project='+project,'--format','{{.ID}}']).stdout.strip()
 assert not raw(['ps','--all','--filter','label=io.aegis.worker-proof='+nonce,'--format','{{.ID}}']).stdout.strip()
 assert not raw(['volume','ls','--filter','label=com.docker.compose.project='+project,'--format','{{.Name}}']).stdout.strip()
 assert raw(['volume','inspect',secret_volume],success=False).returncode!=0
 assert not raw(['network','ls','--filter','label=com.docker.compose.project='+project,'--format','{{.ID}}']).stdout.strip()
 assert work_root is not None and not work_root.exists()
 if broker is not None:broker.verify_removed()
 evidence['owned_fixture_resources_cleaned']=True
 if admission_mode:
  destination=os.environ.get('AEGIS_PACKAGED_WORKER_EVIDENCE')
  if destination:
   from packaged_authorizer_fixture import write_private_admission_evidence
   write_private_admission_evidence(destination,evidence)
  else:
   with tempfile.NamedTemporaryFile(mode='w',prefix='aegis-admitted-private-',suffix='.json',delete=False) as output:json.dump(evidence,output,indent=2);output.write('\n')
  print('packaged_worker_checks: '+str(len(checks)),flush=True)
 else:
  path=pathlib.Path(os.environ.get('AEGIS_PACKAGED_WORKER_EVIDENCE',str(ROOT/('docs/evidence/bound-authorizer-acceptance.json' if controller_gate_mode else 'docs/evidence/tls-broker-acceptance.json' if authz_mode else 'docs/evidence/broker-dispatch-acceptance.json' if broker_mode else 'docs/evidence/journal-bound-worker-acceptance.json'))));path.write_text(json.dumps(evidence,indent=2)+'\n');print('packaged_worker_checks: '+str(len(checks)),flush=True)
