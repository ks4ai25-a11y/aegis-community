# SPDX-License-Identifier: BUSL-1.1
"""Separate controller-observed authorizer, only in the explicit Linux CI fixture.

No daemon socket/client identity is mounted in the authorizer. Private runtime
payloads remain in memory/files; public output is test names and statuses only.
"""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import hashlib,json,os,pathlib,re,sqlite3,subprocess,time
from engine_authz_acceptance import run,ROOT

class BoundAuthorizer:
 def __init__(self,engine,raw,compose,project,nonce,owner,socket_volume,provisioning):
  from packaged_engine_fixture import require_ci
  require_ci()
  if os.environ.get('AEGIS_PACKAGED_CONTROLLER_GATE_TEST')!='1':raise RuntimeError('Explicit disposable controller gate fixture only')
  self.engine,self.raw,self.compose=engine,raw,compose
  self.name=project+'-authorizer';self.nonce=nonce;self.volume=project+'-observer-credential';self.created=False;self.volume_created=False
  self.owner=owner;self.verifier='observer-'+nonce
  self.credential_mount='/run/observer-credential';self.admitted=False;self.ledger_verified=False
  self.registry=engine.work/'aegis-scanner-workspaces-10001'
  self.digest=provisioning['engine_digest'];self.registry_digest=provisioning['registry_digest']
  if not re.fullmatch(r'sha256:[0-9a-f]{64}',self.digest) or not re.fullmatch(r'sha256:[0-9a-f]{64}',self.registry_digest):raise RuntimeError('Approved scope required')
  self.image=raw(['image','inspect','aegis-community/scanner-authorizer:0.1.0-alpha.1','--format','{{.Id}}']).stdout.strip()
  if not re.fullmatch(r'sha256:[0-9a-f]{64}',self.image):raise RuntimeError('Pinned authorizer image unavailable')
  self.journal=engine.plugin_root/'bound-journal'
  self.args=['serve-bound',str(engine.plugin_socket),str(self.journal),self.digest,str(self.registry),'10001','10001','/opt/aegis/tools/scanners.lock.json','/run/scanner/worker.sock','/run/observer-credential/observer.credential',owner,self.verifier,self.registry_digest,'-']
  self.mounts=['type=volume,src='+socket_volume+',dst=/run/scanner,readonly','type=volume,src='+self.volume+',dst=/run/observer-credential,readonly','type=bind,src='+str(self.registry)+',dst='+str(self.registry)+',readonly','type=bind,src='+str(engine.plugin_root)+',dst='+str(engine.plugin_root)]
 def command(self,name,args):
  cmd=['run','--pull=never','--name',name,'--label','io.aegis.worker-proof='+self.nonce,'--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--pids-limit','64','--cpus','1','--log-driver','none']
  for mount in self.mounts:cmd+=['--mount',mount]
  return cmd+[self.image,*args]
 def start(self):
  # Provision the empty registry before Docker resolves the read-only bind.
  # The worker normally creates it only after claim, which is deliberately
  # later than authorizer readiness. Refuse an existing path; never repair or
  # clear another registry, and create it as the actual scanner UID.
  namespace=json.loads(run(self.engine.as_user([self.engine.programs/'aegis-research','workspace-registry-init',self.registry]),env=self.engine.env).stdout)
  self.namespace=namespace['registry_namespace_digest']
  if not re.fullmatch(r'sha256:[0-9a-f]{64}',self.namespace):raise RuntimeError('Original registry namespace unavailable')
  self.raw(['volume','create','--label','io.aegis.worker-proof='+self.nonce,self.volume]);self.volume_created=True
  assert json.loads(self.raw(['volume','inspect',self.volume]).stdout)[0]['Labels']['io.aegis.worker-proof']==self.nonce
  # Metadata-only preflight used an unused unbound journal. Retain it intact;
  # the bound plugin gets its own namespace under the actual approved engine.
  for item in self.engine.processes:
   if item[2]==self.engine.programs/'aegis-engine-authz':self.engine.process_stop(item)
  run(self.engine.as_user([self.engine.programs/'aegis-engine-authz','init',self.journal,self.digest]),env=self.engine.env)
  self.provision_credentials()
  cmd=self.command(self.name,self.args);cmd.insert(1,'--detach')
  self.raw(cmd);self.created=True
  self.wait_ready()
  self.assert_isolation()
  self.assert_compose()
  self.engine.journal=self.journal;self.engine.engine_digest=self.digest
 def provision_credentials(self):
  self.compose('run','--rm','--no-deps','--volume',self.volume+':/run/scanner','--entrypoint','aegisctl','init','scanner-verifier','enroll',self.verifier,'10',self.digest,self.registry_digest,'/run/scanner/observer.credential')
 def wait_ready(self):
  for _ in range(60):
   state=json.loads(self.raw(['inspect',self.name]).stdout)[0]
   if not state['State']['Running']:raise RuntimeError('Owned bound authorizer stopped before readiness')
   if subprocess.run(['sudo','test','-S',self.engine.plugin_socket],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
    try:status,_=self.engine.observer('/info')
    except (OSError,TimeoutError):status=None
    if status==200:return
   time.sleep(.1)
  raise RuntimeError('Owned controller-observed authorizer unavailable')
 def assert_isolation(self):
  c=json.loads(self.raw(['inspect',self.name]).stdout)[0];h=c['HostConfig'];m={x['Destination']:x for x in c['Mounts']}
  assert c['Config']['User']=='10001:10001' and c['Config']['Entrypoint']==['/aegis-engine-authz'] and c['Image']==self.image
  assert h['NetworkMode']=='none' and h['ReadonlyRootfs'] and h['CapDrop']==['ALL'] and not h['Privileged'] and not h['GroupAdd'] and h['RestartPolicy']['Name']=='no'
  assert not h['CapAdd'] and h['SecurityOpt']==['no-new-privileges'] and h['PidsLimit']==64 and h['Memory']==256*1024*1024 and h['NanoCpus']==1000000000 and h['LogConfig']['Type']=='none'
  assert set(m)=={'/run/scanner',self.credential_mount,str(self.registry),str(self.engine.plugin_root)}
  assert not m['/run/scanner']['RW'] and not m[self.credential_mount]['RW'] and not m[str(self.registry)]['RW'] and m[str(self.engine.plugin_root)]['RW']
  assert c['Config']['Labels']['io.aegis.worker-proof']==self.nonce
  assert not any(x.startswith(('DOCKER_HOST=','DOCKER_CONTEXT=','AEGIS_SCANNER_ENGINE_TLS_DIR=')) for x in c['Config'].get('Env',[]) or [])
  broker=json.loads(self.raw(['inspect',self.name.removesuffix('-authorizer')+'-broker']).stdout)[0]
  assert not any(x.get('Name')==self.volume or x['Source']==str(self.engine.plugin_root) for x in broker['Mounts'])
 def assert_compose(self):
  env={**self.engine.env,'AEGIS_SCANNER_AUTHORIZER_ROOT':str(self.engine.plugin_root),'AEGIS_SCANNER_ENGINE_DIGEST':self.digest,'AEGIS_SCANNER_REGISTRY_ROOT':str(self.registry),'AEGIS_SCANNER_OWNER':self.owner,'AEGIS_SCANNER_OBSERVER_ID':self.verifier,'AEGIS_SCANNER_REGISTRY_DIGEST':self.registry_digest,'AEGIS_SCANNER_OBSERVER_VOLUME':self.volume,'AEGIS_SCANNER_RULES_DIGEST':'-'}
  result=run(['docker','compose','-f',ROOT/'deploy/compose.demo.yaml','-f',ROOT/'deploy/compose.scanner-authorizer.yaml','--profile','operator-engine-gate','config','--format','json'],env=env,cwd=ROOT)
  c=json.loads(result.stdout)['services']['scanner-authorizer']
  assert c['command']==self.args and c['profiles']==['operator-engine-gate'] and c['network_mode']=='none' and c['read_only'] and c['cap_drop']==['ALL'] and not c.get('group_add') and not c.get('environment')
  assert {m['target'] for m in c['volumes']}=={'/run/scanner',self.credential_mount,str(self.registry),str(self.engine.plugin_root)}
  assert all(m.get('read_only') for m in c['volumes'] if m['target']!=str(self.engine.plugin_root))
 def probe_unregistered(self):
  binary=self.engine.programs/'aegis-engine-gate-tests'
  # The probe is a native trusted CI client, not a shipped command or a tool.
  env={'GITHUB_ACTIONS':'true','AEGIS_PACKAGED_CONTROLLER_GATE_TEST':'1','AEGIS_GATE_PROBE_ENDPOINT':self.engine.endpoint,'AEGIS_GATE_PROBE_TLS':str(self.engine.client_dir),'AEGIS_GATE_PROBE_REGISTRY':str(self.registry),'AEGIS_GATE_PROBE_JOURNAL':str(self.journal),'AEGIS_GATE_PROBE_LOCK':str(self.engine.programs/'scanners.lock.json')}
  args=self.engine.as_user(['/usr/bin/env',*[k+'='+v for k,v in env.items()],binary,'-test.run=^TestRealPackagedGateRefusesUnregisteredLaunch$','-test.v'])
  try:result=subprocess.run(args,env=self.engine.env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
  except subprocess.TimeoutExpired:raise RuntimeError('Private unregistered-launch probe exceeded its bound; fixture retained') from None
  # No runtime payloads or private configuration are copied into public logs.
  if result.returncode or b'--- PASS: TestRealPackagedGateRefusesUnregisteredLaunch' not in result.stdout:raise RuntimeError('Actual engine unregistered-launch probe failed or did not run')
 def stop(self):
  if not self.created:return
  response=self.raw(['inspect',self.name],success=False)
  if response.returncode!=0:return
  c=json.loads(response.stdout)[0]
  if c['Config']['Labels'].get('io.aegis.worker-proof')!=self.nonce or c['Image']!=self.image:raise RuntimeError('Authorizer identity changed')
  if c['State']['Running']:self.raw(['stop','--time','10',self.name],30)
 def prove_failure_and_seal(self):
  self.stop()
  # Match the existing standalone plugin-loss check's bounded allowance for
  # the daemon's plugin transport retries. No mutation is retried.
  status,_=self.engine.observer('/info',timeout=45)
  assert status==500
  # This exact used namespace cannot be served without its sealed configuration.
  name=self.name+'-downgrade'
  args=['serve',*self.args[1:8]]
  try:
   result=self.raw(self.command(name,args),20,False)
   assert result.returncode==1
  finally:self.remove_owned(name)
 def remove_owned(self,name):
  response=self.raw(['inspect',name],success=False)
  if response.returncode!=0:return
  c=json.loads(response.stdout)[0]
  if c['Config']['Labels'].get('io.aegis.worker-proof')!=self.nonce or c['Image']!=self.image:raise RuntimeError('Authorizer fixture identity changed')
  if c['State']['Running']:self.raw(['stop','--time','10',name],30)
  self.raw(['rm',name])
 def cleanup(self):
  self.stop()
  if self.created:self.remove_owned(self.name);self.created=False
  if self.volume_created:
   m=json.loads(self.raw(['volume','inspect',self.volume]).stdout)[0];assert m['Labels']['io.aegis.worker-proof']==self.nonce
   self.raw(['volume','rm',self.volume]);self.volume_created=False

class AdmittedAuthorizer(BoundAuthorizer):
 """Same isolated daemon, now with separately enrolled durable admission."""
 def __init__(self,engine,raw,compose,project,nonce,owner,socket_volume,provisioning,worker):
  super().__init__(engine,raw,compose,project,nonce,owner,socket_volume,provisioning)
  if os.environ.get('AEGIS_PACKAGED_ADMISSION_TEST')!='1' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',worker or ''):raise RuntimeError('Explicit selected admission fixture required')
  old_volume=self.volume;old_mount=self.credential_mount
  self.volume=project+'-authorizer-credential';self.credential_mount='/run/authorizer-credential';self.authorizer='authorizer-'+nonce;self.worker=worker;self.socket_volume=socket_volume;self.admitted=True;self.mediation_verified=False
  self.mounts=[m.replace('src='+old_volume+',','src='+self.volume+',').replace('dst='+old_mount+',','dst='+self.credential_mount+',') for m in self.mounts]
 def engine_state(self):
  """Root-only digest of the dedicated daemon's own data root, read beside the
  API rather than through it. Only the digest leaves the private fixture."""
  # Layer/snapshot trees are listed, not read: a new or removed image changes
  # their membership and the content/metadata stores, which are hashed.
  script=('import hashlib,os,sys\nroot=sys.argv[1];h=hashlib.sha256()\n'
   'for d,dirs,files in os.walk(root):\n'
   ' dirs.sort();rel=os.path.relpath(d,root)\n'
   ' if rel=="tmp" or rel.startswith("tmp"+os.sep):dirs[:]=[];continue\n'
   ' for n in sorted(dirs+files):\n'
   '  p=os.path.join(d,n);s=os.lstat(p);h.update((os.path.relpath(p,root)+":"+oct(s.st_mode)+":"+(str(s.st_size) if not os.path.isdir(p) else "")+"\\n").encode())\n'
   '  if os.path.isfile(p) and not os.path.islink(p) and s.st_size<=16777216:\n'
   '   with open(p,"rb") as f:h.update(hashlib.sha256(f.read()).digest())\n'
   ' if os.path.basename(d) in ("snapshots","overlay2","diff"):dirs[:]=[]\n'
   'print(h.hexdigest())\n')
  value=run(['sudo','/usr/bin/python3','-I','-c',script,self.engine.root/'data'],env=self.engine.env).stdout.decode().strip()
  if not re.fullmatch(r'[0-9a-f]{64}',value):raise RuntimeError('Private engine state digest unavailable')
  return value
 def assert_single_api_listener(self):
  """The dedicated daemon serves its API only on the one TLS port, and every
  other Unix listener in the fixture root is unreachable by the scanner UID."""
  pid=self.engine.pidfile.read_text().strip()
  if not re.fullmatch(r'[1-9][0-9]*',pid):raise RuntimeError('Private daemon identity unavailable')
  owned=lambda line:'pid='+pid+',' in line
  tcp=[l.split()[3] for l in run(['sudo','ss','-Hltnp'],env=self.engine.env).stdout.decode().splitlines() if owned(l)]
  if tcp!=[self.engine.endpoint.removeprefix('https://')]:raise RuntimeError('Dedicated daemon has an unexpected TCP listener')
  unix=[l.split()[4] for l in run(['sudo','ss','-Hlxp'],env=self.engine.env).stdout.decode().splitlines() if len(l.split())>4]
  allowed={str(self.engine.plugin_socket),self.engine.socket}
  for path in unix:
   if path.startswith(str(self.engine.root)+'/') and path not in allowed:
    if subprocess.run(self.engine.as_user(['/usr/bin/test','-e',path]),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:raise RuntimeError('Private engine listener reachable by the scanner UID')
  if any(owned(l) and not l.split()[4].startswith(str(self.engine.root)+'/') for l in run(['sudo','ss','-Hlxp'],env=self.engine.env).stdout.decode().splitlines() if len(l.split())>4):raise RuntimeError('Dedicated daemon has a Unix listener outside its private roots')
 def probe_unadmitted_writes(self):
  """Send the enumerated unadmitted write surface to the actual admitted
  engine as broker and observer; require plugin refusal and no state change."""
  import shutil
  identity=self.engine.root/'observer-probe';identity.mkdir(mode=0o700)
  for source,target in [('ca.pem','ca.pem'),('observer.pem','client.pem'),('observer.key','client.key')]:
   shutil.copyfile(self.engine.tls/source,identity/target);(identity/target).chmod(0o600)
  run(['sudo','chown','-R','10001:10001',identity])
  self.assert_single_api_listener()
  before=self.engine_state();time.sleep(3)
  if self.engine_state()!=before:raise RuntimeError('Dedicated engine state is not quiescent before the mediation probe')
  binary=self.engine.programs/'aegis-engine-gate-tests'
  env={'GITHUB_ACTIONS':'true','AEGIS_PACKAGED_CONTROLLER_GATE_TEST':'1','AEGIS_PACKAGED_ADMISSION_TEST':'1','AEGIS_GATE_PROBE_ENDPOINT':self.engine.endpoint,'AEGIS_GATE_PROBE_TLS':str(self.engine.client_dir),'AEGIS_GATE_PROBE_OBSERVER_TLS':str(identity),'AEGIS_GATE_PROBE_JOURNAL':str(self.journal),'AEGIS_GATE_PROBE_LOCK':str(self.engine.programs/'scanners.lock.json')}
  args=self.engine.as_user(['/usr/bin/env',*[k+'='+v for k,v in env.items()],binary,'-test.run=^TestRealPackagedEngineRefusesUnadmittedWrites$','-test.v'])
  try:result=subprocess.run(args,env=self.engine.env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
  except subprocess.TimeoutExpired:raise RuntimeError('Private unadmitted-write probe exceeded its bound; fixture retained') from None
  # Only the Go test's own failure line is public; it names a class and method,
  # never a runtime path, identity or engine payload.
  if result.returncode or b'--- PASS: TestRealPackagedEngineRefusesUnadmittedWrites' not in result.stdout:
   for line in result.stdout.decode(errors='replace').splitlines():
    if re.fullmatch(r'\s+packaged_mediation_real_test\.go:\d+: [A-Za-z0-9 .()_-]{1,160}',line):print(line.strip(),flush=True)
   raise RuntimeError('Actual engine unadmitted-write probe failed or did not run')
  if self.engine_state()!=before:raise RuntimeError('Refused writes changed dedicated engine state')
  self.assert_single_api_listener()
  self.mediation_verified=True
 def provision_credentials(self):
  # Copy only the image's owned0700 /run/scanner directory metadata into this
  # fresh labelled credential volume. No observer credential is minted/mounted.
  self.compose('run','--rm','--no-deps','--volume',self.volume+':/run/scanner','--entrypoint','aegisctl','init','--version')
  self.args=['serve-admitted',str(self.engine.plugin_socket),str(self.journal),self.digest,str(self.registry),'10001','10001','/opt/aegis/tools/scanners.lock.json','/run/scanner/worker.sock',self.credential_mount+'/authorizer.credential',self.owner,self.authorizer,self.registry_digest,self.namespace,'-']
  name=self.name+'-policy'
  try:
   result=self.raw(self.command(name,['admitted-policy-input',*self.args[1:]]),30)
   policy=json.loads(result.stdout);self.policy=policy.pop('policy_digest')
   if not re.fullmatch(r'sha256:[0-9a-f]{64}',self.policy) or policy!={'schema_version':'1.0','controller_binding_verified':False,'engine_write_authorized':False,'cleanup_release_authorized':False}:raise RuntimeError('Private native policy input invalid')
  finally:self.remove_owned(name)
  self.compose('run','--rm','--no-deps','--volume',self.volume+':/run/scanner','--entrypoint','aegisctl','init','scanner-authorizer','enroll',self.authorizer,'10',self.digest,self.registry_digest,self.policy,'/run/scanner/authorizer.credential')
  self.compose('exec','-T','controller','aegisctl','scanner-authorizer','bind',self.authorizer,self.namespace)
  self.assert_roles()
 def assert_roles(self):
  def probe(volume,credential,role,success):
   return self.compose('run','--rm','--no-deps','--volume',self.socket_volume+':/run/controller:ro','--volume',volume+':/run/scanner:ro','--env','AEGIS_SCANNER_SOCKET=/run/controller/worker.sock','--entrypoint','aegisctl','init',role,'probe','/run/scanner/'+credential,success=success)
  probe(self.volume,'authorizer.credential','scanner-authorizer',True)
  for role in ('scanner-worker','scanner-verifier'):
   if probe(self.volume,'authorizer.credential',role,False).returncode!=1:raise RuntimeError('Authorizer inherited another role')
  worker_volume=self.name.removesuffix('-authorizer')+'-credential'
  if probe(worker_volume,'worker.credential','scanner-authorizer',False).returncode!=1:raise RuntimeError('Worker credential inherited authorizer authority')
 def assert_compose(self):
  env={**self.engine.env,'AEGIS_SCANNER_AUTHORIZER_ROOT':str(self.engine.plugin_root),'AEGIS_SCANNER_ENGINE_DIGEST':self.digest,'AEGIS_SCANNER_REGISTRY_ROOT':str(self.registry),'AEGIS_SCANNER_OWNER':self.owner,'AEGIS_SCANNER_AUTHORIZER_ID':self.authorizer,'AEGIS_SCANNER_REGISTRY_DIGEST':self.registry_digest,'AEGIS_SCANNER_REGISTRY_NAMESPACE':self.namespace,'AEGIS_SCANNER_ADMISSION_CREDENTIAL_VOLUME':self.volume,'AEGIS_SCANNER_RULES_DIGEST':'-'}
  result=run(['docker','compose','-f',ROOT/'deploy/compose.demo.yaml','-f',ROOT/'deploy/compose.scanner-authorizer-admitted.yaml','--profile','operator-engine-admission','config','--format','json'],env=env,cwd=ROOT)
  c=json.loads(result.stdout)['services']['scanner-authorizer']
  assert c['command']==self.args and c['profiles']==['operator-engine-admission'] and c['network_mode']=='none' and c['read_only'] and c['cap_drop']==['ALL'] and not c.get('group_add') and not c.get('environment')
  assert {m['target'] for m in c['volumes']}=={'/run/scanner',self.credential_mount,str(self.registry),str(self.engine.plugin_root)}
  assert all(m.get('read_only') for m in c['volumes'] if m['target']!=str(self.engine.plugin_root))
 def verify_ledger(self,path,job,launches):
  """Read only a private consistent snapshot, never dump it to CI output."""
  if self.ledger_verified:raise RuntimeError('Ledger acceptance is one-shot')
  with sqlite3.connect(pathlib.Path(path).as_uri()+'?mode=ro&immutable=1',uri=True) as db:
   db.row_factory=sqlite3.Row
   assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
   bindings=db.execute('SELECT * FROM scanner_mutation_bindings WHERE owner=?',(self.owner,)).fetchall();assert len(bindings)==1;b=bindings[0]
   assert b['state']=='active' and (b['authorizer'],b['engine_digest'],b['registry_digest'],b['policy_digest'],b['namespace_digest'])==(self.authorizer,self.digest,self.registry_digest,self.policy,self.namespace)
   document={key:b[column] for key,column in [('owner_id','owner'),('authorizer_id','authorizer'),('engine_digest','engine_digest'),('registry_digest','registry_digest'),('policy_digest','policy_digest'),('registry_namespace_digest','namespace_digest'),('broker_binding_digest','broker_binding_digest'),('created_at','created_at')]}
   assert b['digest']=='sha256:'+hashlib.sha256(json.dumps(document,separators=(',',':')).encode()).hexdigest()
   role=db.execute('SELECT * FROM scanner_authorizers WHERE id=?',(self.authorizer,)).fetchone();assert role is not None and role['owner']==self.owner and role['state']=='active' and (role['engine_digest'],role['registry_digest'],role['policy_digest'])==(self.digest,self.registry_digest,self.policy)
   assert db.execute('SELECT state FROM scanner_jobs WHERE id=?',(job,)).fetchone()[0]=='completed'
   broker=json.loads(db.execute("SELECT value FROM settings WHERE key='scanner_engine_broker_binding'").fetchone()[0]);assert broker['document']['worker_id']==self.worker and broker['broker_binding_digest']==b['broker_binding_digest']
   dispatch=db.execute('SELECT * FROM scanner_dispatch WHERE job=?',(job,)).fetchone();assert dispatch is not None and dispatch['state']=='cleanup_required'
   generations=db.execute('SELECT * FROM scanner_allocation_generations').fetchall();assert len(generations)==1;g=generations[0]
   assert g['job']==job and g['owner']==self.owner and g['worker']==self.worker and g['state']=='closed' and g['closed_at'] and re.fullmatch(r'[0-9a-f]{64}',g['id'])
   self.generation,self.binding_digest=g['id'],b['digest']
   assert g['binding_digest']==b['digest'] and g['lease_hash']==dispatch['token_hash'] and g['deadline']==dispatch['deadline'] and g['guard_digest']==dispatch['guard_set_digest']
   assert len(launches)==1 and launches[0]['document']['plan']['tool_id']=='bandit';launch=launches[0];name=launch['document']['plan']['container_id'];assert g['guard_digest']==launch['document']['guard_set_digest']
   workspace=db.execute('SELECT digest FROM scanner_workspaces WHERE job=? AND tool=?',(job,'bandit')).fetchone()[0]
   intents=db.execute('SELECT * FROM scanner_mutation_intents WHERE generation=? ORDER BY operation',(g['id'],)).fetchall();assert len(intents)==3 and {m['operation'] for m in intents}=={'create','start','remove'}
   def journal_record(path):
    raw=run(self.engine.as_user(['/usr/bin/cat',path]),env=self.engine.env).stdout
    assert len(raw)<=4096
    value=json.loads(raw);assert set(value)=={'digest','document'}
    assert value['digest']=='sha256:'+hashlib.sha256(json.dumps(value['document'],separators=(',',':')).encode()).hexdigest()
    return value
   for m in intents:
    op=m['operation'];assert m['job']==job and m['tool']=='bandit' and m['state']=='completed' and m['container']==name and m['launch_digest']==launch['launch_digest'] and m['workspace_digest']==workspace
    assert m['response_status']==(201 if op=='create' else 204) and re.fullmatch(r'[0-9a-f]{64}',m['result_engine_id']) and re.fullmatch(r'sha256:[0-9a-f]{64}',m['descriptor_digest'])
    assert m['target_engine_id']==('' if op=='create' else m['result_engine_id'])
    pending=journal_record(self.journal/name/(op+'.pending.json'))
    native=journal_record(self.journal/name/(op+'.response.json'))
    proposed=pending['document']['controller_intent'];assert proposed['intent_id']==m['id'] and proposed['state']=='pending' and proposed['request']['generation_id']==g['id'] and proposed['request']['descriptor_digest']==m['descriptor_digest'] and proposed['request']['job_id']==job and proposed['request']['operation']==op and proposed['request']['launch_digest']==m['launch_digest'] and proposed['workspace_digest']==m['workspace_digest'] and proposed['container']==name
    assert native['document']['intent_digest']==pending['digest'] and native['document']['container_id']==m['result_engine_id'] and native['document']['response_status']==m['response_status'] and native['digest']==m['response_digest']
   assert len({m['result_engine_id'] for m in intents})==1
   self.created_engine_id=intents[0]['result_engine_id']
   seal=journal_record(self.journal/'policy.json')
   expected='sha256:'+hashlib.sha256(json.dumps({'Domain':'aegis-controller-admitted-journal-v1','Policy':self.policy,'Binding':b['digest']},separators=(',',':')).encode()).hexdigest()
   assert seal['document']['local_policy_digest']==expected
  self.ledger_verified=True

def provision_reconciler(engine,bound,raw,compose,nonce,socket_volume,project):
 """Enroll a separate reconciler and write its private config (ADR 057).

 The reconciler receives its own controller credential and the observer's own
 engine TLS identity; never the worker lease, authorizer or broker key."""
 import shutil
 volume=project+'-reconciler-credential';reconciler='reconciler-'+nonce
 raw(['volume','create','--label','io.aegis.worker-proof='+nonce,volume])
 compose('run','--rm','--no-deps','--volume',volume+':/run/scanner','--entrypoint','aegisctl','init','--version')
 compose('run','--rm','--no-deps','--volume',volume+':/run/scanner','--entrypoint','aegisctl','init','scanner-reconciler','enroll',reconciler,'10',bound.binding_digest,'/run/scanner/reconciler.credential')
 identity=engine.root/'observer-client';public=engine.root/'observer-public';config=engine.root/'reconcile'
 for path in (identity,public,config):path.mkdir(mode=0o700)
 for source,target in [('ca.pem','ca.pem'),('observer.pem','client.pem'),('observer.key','client.key')]:
  shutil.copyfile(engine.tls/source,identity/target);(identity/target).chmod(0o600)
 shutil.copyfile(engine.tls/'broker.pem',public/'broker.pem');(public/'broker.pem').chmod(0o600)
 document={'controller_socket':'/run/scanner/worker.sock','reconciler_credential_file':'/run/reconciler-credential/reconciler.credential','owner_id':bound.owner,'reconciler_id':reconciler,'binding_digest':bound.binding_digest,'engine_digest':bound.digest,'registry_digest':bound.registry_digest,'policy_digest':bound.policy,'registry_namespace_digest':bound.namespace,'canonical_aegis_source_root':'/opt/aegis','canonical_workspace_registry':str(bound.registry),'observer_endpoint':'unix:///run/engine/docker.sock','observer_identity_directory':str(identity),'broker_certificate_file':str(public/'broker.pem')}
 (config/'config.json').write_text(json.dumps(document));(config/'config.json').chmod(0o600)
 for path in (identity,public,config):run(['sudo','chown','-R','10001:10001',path])
 mounts=['type=volume,src='+socket_volume+',dst=/run/scanner,readonly','type=volume,src='+volume+',dst=/run/reconciler-credential,readonly','type=bind,src='+engine.socket+',dst=/run/engine/docker.sock,readonly','type=bind,src='+str(bound.registry)+',dst='+str(bound.registry)+',readonly']
 mounts+=['type=bind,src='+str(p)+',dst='+str(p)+',readonly' for p in (identity,public,config)]
 return volume,str(config/'config.json'),mounts

def write_private_admission_evidence(path,value):
 """Create one new private receipt under an existing owned0700 directory."""
 import stat
 descriptor=None;parent=None
 try:
  path=pathlib.Path(path)
  if not path.is_absolute() or path.parent.resolve(strict=True)!=path.parent:raise ValueError('canonical parent')
  before=path.parent.lstat()
  if not stat.S_ISDIR(before.st_mode) or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o700:raise ValueError('private parent')
  parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  if not os.path.samestat(before,os.fstat(parent)):raise ValueError('parent identity')
  descriptor=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
  info=os.fstat(descriptor)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('private receipt')
  with os.fdopen(descriptor,'w',encoding='utf-8') as output:
   descriptor=None;json.dump(value,output,indent=2);output.write('\n');output.flush();os.fsync(output.fileno())
  if not os.path.samestat(before,path.parent.lstat()):raise ValueError('parent replacement')
  os.fsync(parent)
 except (OSError,ValueError,TypeError):raise RuntimeError('Private admission evidence delivery refused; original records retained') from None
 finally:
  if descriptor is not None:os.close(descriptor)
  if parent is not None:os.close(parent)
