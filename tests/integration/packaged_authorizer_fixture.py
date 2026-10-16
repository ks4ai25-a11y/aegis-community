"""Separate controller-observed authorizer, only in the explicit Linux CI fixture.

No daemon socket/client identity is mounted in the authorizer. Private runtime
payloads remain in memory/files; public output is test names and statuses only.
"""
import json,os,pathlib,re,subprocess,time
from engine_authz_acceptance import run,ROOT

class BoundAuthorizer:
 def __init__(self,engine,raw,compose,project,nonce,owner,socket_volume,provisioning):
  from packaged_engine_fixture import require_ci
  require_ci()
  if os.environ.get('AEGIS_PACKAGED_CONTROLLER_GATE_TEST')!='1':raise RuntimeError('Explicit disposable controller gate fixture only')
  self.engine,self.raw,self.compose=engine,raw,compose
  self.name=project+'-authorizer';self.nonce=nonce;self.volume=project+'-observer-credential';self.created=False;self.volume_created=False
  self.owner=owner;self.verifier='observer-'+nonce
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
  run(self.engine.as_user(['/usr/bin/mkdir','-m','700',self.registry]),env=self.engine.env)
  self.raw(['volume','create','--label','io.aegis.worker-proof='+self.nonce,self.volume]);self.volume_created=True
  assert json.loads(self.raw(['volume','inspect',self.volume]).stdout)[0]['Labels']['io.aegis.worker-proof']==self.nonce
  self.compose('run','--rm','--no-deps','--volume',self.volume+':/run/scanner','--entrypoint','aegisctl','init','scanner-verifier','enroll',self.verifier,'10',self.digest,self.registry_digest,'/run/scanner/observer.credential')
  # Metadata-only preflight used an unused unbound journal. Retain it intact;
  # the bound plugin gets its own namespace under the actual approved engine.
  for item in self.engine.processes:
   if item[2]==self.engine.programs/'aegis-engine-authz':self.engine.process_stop(item)
  run(self.engine.as_user([self.engine.programs/'aegis-engine-authz','init',self.journal,self.digest]),env=self.engine.env)
  cmd=self.command(self.name,self.args);cmd.insert(1,'--detach')
  self.raw(cmd);self.created=True
  self.wait_ready()
  self.assert_isolation()
  self.assert_compose()
  self.engine.journal=self.journal;self.engine.engine_digest=self.digest
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
  assert set(m)=={'/run/scanner','/run/observer-credential',str(self.registry),str(self.engine.plugin_root)}
  assert not m['/run/scanner']['RW'] and not m['/run/observer-credential']['RW'] and not m[str(self.registry)]['RW'] and m[str(self.engine.plugin_root)]['RW']
  assert c['Config']['Labels']['io.aegis.worker-proof']==self.nonce
  assert not any(x.startswith(('DOCKER_HOST=','DOCKER_CONTEXT=','AEGIS_SCANNER_ENGINE_TLS_DIR=')) for x in c['Config'].get('Env',[]) or [])
  broker=json.loads(self.raw(['inspect',self.name.removesuffix('-authorizer')+'-broker']).stdout)[0]
  assert not any(x.get('Name')==self.volume or x['Source']==str(self.engine.plugin_root) for x in broker['Mounts'])
 def assert_compose(self):
  env={**self.engine.env,'AEGIS_SCANNER_AUTHORIZER_ROOT':str(self.engine.plugin_root),'AEGIS_SCANNER_ENGINE_DIGEST':self.digest,'AEGIS_SCANNER_REGISTRY_ROOT':str(self.registry),'AEGIS_SCANNER_OWNER':self.owner,'AEGIS_SCANNER_OBSERVER_ID':self.verifier,'AEGIS_SCANNER_REGISTRY_DIGEST':self.registry_digest,'AEGIS_SCANNER_OBSERVER_VOLUME':self.volume,'AEGIS_SCANNER_RULES_DIGEST':'-'}
  result=run(['docker','compose','-f',ROOT/'deploy/compose.demo.yaml','-f',ROOT/'deploy/compose.scanner-authorizer.yaml','--profile','operator-engine-gate','config','--format','json'],env=env,cwd=ROOT)
  c=json.loads(result.stdout)['services']['scanner-authorizer']
  assert c['command']==self.args and c['profiles']==['operator-engine-gate'] and c['network_mode']=='none' and c['read_only'] and c['cap_drop']==['ALL'] and not c.get('group_add') and not c.get('environment')
  assert {m['target'] for m in c['volumes']}=={'/run/scanner','/run/observer-credential',str(self.registry),str(self.engine.plugin_root)}
  assert all(m.get('read_only') for m in c['volumes'] if m['target']!=str(self.engine.plugin_root))
 def probe_unregistered(self):
  binary=self.engine.programs/'aegis-engine-gate-tests'
  # The probe is a native trusted CI client, not a shipped command or a tool.
  env={'GITHUB_ACTIONS':'true','AEGIS_PACKAGED_CONTROLLER_GATE_TEST':'1','AEGIS_GATE_PROBE_ENDPOINT':self.engine.endpoint,'AEGIS_GATE_PROBE_TLS':str(self.engine.client_dir),'AEGIS_GATE_PROBE_REGISTRY':str(self.registry),'AEGIS_GATE_PROBE_JOURNAL':str(self.journal),'AEGIS_GATE_PROBE_LOCK':str(self.engine.programs/'scanners.lock.json')}
  args=self.engine.as_user(['/usr/bin/env',*[k+'='+v for k,v in env.items()],binary,'-test.run=^TestRealPackagedGateRefusesUnregisteredLaunch$','-test.v'])
  result=subprocess.run(args,env=self.engine.env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
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
