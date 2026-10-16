"""TLS-only dedicated scanner engine for an explicitly enabled packaged CI run.

The package/orchestration daemon is untouched. The second daemon has a new data
root, its own authorization plugin/journal and a credential-free Unix byte relay.
"""
import hashlib,json,os,pathlib,platform,re,secrets,shutil,socket,ssl,subprocess,sys,tempfile,time,urllib.error,urllib.request
from engine_authz_acceptance import certificate,run,ROOT

def require_ci():
 if os.environ.get('AEGIS_PACKAGED_ENGINE_AUTHZ_TEST')!='1' or os.environ.get('AEGIS_PACKAGED_BROKER_TEST')!='1' or os.environ.get('GITHUB_ACTIONS')!='true' or platform.system()!='Linux' or platform.machine() not in ('x86_64','amd64') or os.geteuid()<=0:raise RuntimeError('Explicit packaged TLS engine GitHub Linux AMD64 CI only')

class EngineFixture:
 def __init__(self,work_root):
  require_ci();self.work=pathlib.Path(work_root);self.processes=[];self.logs=[];self.daemon=None;self.spec=None;self.installed=False;self.finished=False;self.proof=None
  self.root=pathlib.Path(tempfile.mkdtemp(prefix='aegis-packaged-engine-',dir='/tmp')).resolve();self.root.chmod(0o711)
  self.programs=self.root/'programs';self.programs.mkdir(mode=0o755)
  for name in ('aegis-engine-authz','aegis-engine-relay','aegis-research'):
   shutil.copyfile(ROOT/'bin'/name,self.programs/name);(self.programs/name).chmod(0o755)
  shutil.copyfile(ROOT/'tools/scanners.lock.json',self.programs/'scanners.lock.json');(self.programs/'scanners.lock.json').chmod(0o644)
  self.engine=pathlib.Path(os.environ['AEGIS_CI_ENGINE_ROOT']).resolve(strict=True)
  receipt=json.loads((self.engine/'prepared.json').read_text());lock=json.loads((ROOT/'tools/ci-engine.lock.json').read_text())
  if receipt['scope']!='disposable_github_linux_amd64_ci_only' or receipt['archive_digest']!=lock['sha256'] or receipt['version']!=lock['version']:raise RuntimeError('Pinned disposable CI engine required')
  self.engine_receipt=receipt;self.env={k:v for k,v in os.environ.items() if k not in {'DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION','AEGIS_SCANNER_ENGINE_TLS_DIR'}};self.env['PATH']=str(self.engine/'bin')+':'+self.env['PATH']
  self.pidfile=self.root/'dockerd.pid';self.tls=self.root/'tls';self.tls.mkdir(mode=0o700)
  self.client_dir=self.root/'broker-client';self.plugin_root=self.root/'plugin';self.relay_root=self.root/'relay'
  for path in [self.client_dir,self.plugin_root,self.relay_root]:path.mkdir(mode=0o700)
  self.bootstrap=self.root/'bootstrap.sock';self.socket=str(self.relay_root/'docker.sock')
  try:self.start()
  except BaseException:self.close();raise
 def daemon_start(self,extra,label):
  log=(self.root/(label+'.log')).open('xb');self.logs.append(log)
  args=['sudo','env','PATH='+self.env['PATH'],'GODEBUG=http2server=0',str(self.engine/'bin/dockerd'),'--data-root='+str(self.root/'data'),'--exec-root='+str(self.root/'exec'),'--pidfile='+str(self.pidfile),'--bridge=none','--iptables=false','--ip6tables=false','--ip-forward=false','--ip-masq=false','--userland-proxy=false']+extra
  self.daemon=subprocess.Popen(args,env=self.env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
 def daemon_stop(self):
  if self.daemon is not None and self.daemon.poll() is None:
   pid=self.pidfile.read_text().strip()
   if not re.fullmatch(r'[1-9][0-9]*',pid):raise RuntimeError('Private daemon identity unavailable')
   run(['sudo','kill','-TERM',pid]);self.daemon.wait(timeout=35)
  self.daemon=None
 def as_user(self,args):
  return ['sudo','setpriv','--reuid=10001','--regid=10001','--clear-groups',*[str(x) for x in args]]
 def process_start(self,binary,args,parent,label):
  pidfile=parent/(label+'.pid');log=(self.root/(label+'.log')).open('xb');self.logs.append(log)
  # The private owned PID file records the child after dropping UID; no generic
  # process enumeration or ambient daemon selection is used for shutdown.
  script='import os,sys;f=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(f,str(os.getpid()).encode());os.fsync(f);os.close(f);os.execv(sys.argv[2],sys.argv[2:])'
  process=subprocess.Popen(self.as_user(['/usr/bin/python3','-c',script,pidfile,binary,*args]),env=self.env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
  self.processes.append((process,pidfile,binary));return process
 def process_stop(self,item):
  process,pidfile,binary=item
  if process.poll() is not None:return
  pid=run(['sudo','cat',pidfile]).stdout.decode().strip()
  if not re.fullmatch(r'[1-9][0-9]*',pid) or pathlib.Path(run(['sudo','readlink','/proc/'+pid+'/exe']).stdout.decode().strip())!=binary:raise RuntimeError('Owned engine helper process identity changed')
  run(['sudo','kill','-TERM',pid]);process.wait(timeout=15)
 def observer(self,path):
  try:
   with self.opener.open(self.endpoint+'/v1.55'+path,timeout=5) as response:return response.status,json.load(response)
  except urllib.error.HTTPError as e:return e.code,None
 def start(self):
  self.daemon_start(['--host=unix://'+str(self.bootstrap),'--group='+str(os.getegid())],'bootstrap')
  info=None
  for _ in range(60):
   if self.daemon.poll() is not None:raise RuntimeError('Private bootstrap engine exited')
   try:info=json.loads(run([self.engine/'bin/docker','--host','unix://'+str(self.bootstrap),'info','--format','{{json .}}'],env=self.env).stdout);break
   except (subprocess.CalledProcessError,json.JSONDecodeError):time.sleep(1)
  if not info or info.get('OSType')!='linux':raise RuntimeError('Private Linux engine unavailable')
  tool=next(t for t in json.loads((ROOT/'tools/scanners.lock.json').read_text())['tools'] if t['id']=='bandit')
  if not re.fullmatch(r'ghcr.io/pycqa/bandit/bandit@sha256:[0-9a-f]{64}',tool['image']):raise RuntimeError('Pinned Bandit required')
  run([self.engine/'bin/docker','--host','unix://'+str(self.bootstrap),'pull',tool['image']],env=self.env)
  self.daemon_stop()
  if self.bootstrap.exists():raise RuntimeError('Private raw listener remains')
  self.engine_digest='sha256:'+hashlib.sha256(('aegis-authz-daemon-v1\n'+info['ID']).encode()).hexdigest()
  run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',self.tls/'ca.key'])
  run(['openssl','req','-x509','-new','-key',self.tls/'ca.key','-days','1','-sha256','-subj','/CN=Aegis packaged CI engine CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-out',self.tls/'ca.pem'])
  for role,cn in [('server','aegis-scanner-engine'),('broker','aegis-engine-broker'),('observer','aegis-engine-observer')]:certificate(self.tls,role,cn,role=='server')
  for path in self.tls.iterdir():path.chmod(0o600)
  for source,target in [('ca.pem','ca.pem'),('broker.pem','client.pem'),('broker.key','client.key')]:
   shutil.copyfile(self.tls/source,self.client_dir/target);(self.client_dir/target).chmod(0o600)
  for path in [self.client_dir,self.plugin_root,self.relay_root]:run(['sudo','chown','-R','10001:10001',path])
  self.journal=self.plugin_root/'journal';self.plugin_socket=self.plugin_root/'authz.sock'
  run(self.as_user([self.programs/'aegis-engine-authz','init',self.journal,self.engine_digest]),env=self.env)
  plugin=self.process_start(self.programs/'aegis-engine-authz',['serve',self.plugin_socket,self.journal,self.engine_digest,self.work,'10001','10001',self.programs/'scanners.lock.json'],self.plugin_root,'plugin')
  for _ in range(60):
   if plugin.poll() is not None:raise RuntimeError('Private UID plugin process exited before socket readiness')
   if subprocess.run(['sudo','test','-S',self.plugin_socket],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
   time.sleep(.1)
  else:raise RuntimeError('Private plugin socket unavailable')
  name='aegis-packaged-ci-'+secrets.token_hex(12);self.spec=pathlib.Path('/etc/docker/plugins')/(name+'.spec')
  local=self.root/'plugin.spec';local.write_text('unix://'+str(self.plugin_socket)+'\n')
  if self.spec.exists():raise RuntimeError('Plugin discovery name already exists')
  run(['sudo','mkdir','-p',self.spec.parent]);run(['sudo','install','-m','600',local,self.spec]);self.installed=True
  with socket.socket() as selected:selected.bind(('127.0.0.1',0));port=selected.getsockname()[1]
  self.endpoint='https://127.0.0.1:'+str(port)
  self.daemon_start(['--host=tcp://127.0.0.1:'+str(port),'--tlsverify','--tlscacert='+str(self.tls/'ca.pem'),'--tlscert='+str(self.tls/'server.pem'),'--tlskey='+str(self.tls/'server.key'),'--authorization-plugin='+name],'authorized')
  context=ssl.create_default_context(cafile=str(self.tls/'ca.pem'));context.minimum_version=ssl.TLSVersion.TLSv1_3;context.load_cert_chain(str(self.tls/'observer.pem'),str(self.tls/'observer.key'))
  self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
  for _ in range(60):
   if self.daemon.poll() is not None:raise RuntimeError('Private authorized engine exited')
   try:status,actual=self.observer('/info')
   except (OSError,urllib.error.URLError):time.sleep(1);continue
   if status==200 and actual.get('ID')==info['ID']:break
   time.sleep(1)
  else:raise RuntimeError('Original engine TLS identity unavailable')
  self.process_start(self.programs/'aegis-engine-relay',[self.socket,'127.0.0.1:'+str(port)],self.relay_root,'relay')
  for _ in range(60):
   if subprocess.run(['sudo','test','-S',self.socket],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
   time.sleep(.1)
  else:raise RuntimeError('Private opaque relay unavailable')
 def assert_absent(self,name):
  if not re.fullmatch(r'aegis-scan-[0-9a-f]{32}',name):raise RuntimeError('Exact child name required')
  status,_=self.observer('/containers/'+name+'/json')
  if status!=404:raise RuntimeError('Original restricted engine child absence unconfirmed')
 def finish(self):
  # Stop only native relay/plugin and this dedicated daemon. All private keys,
  # journals and engine state remain in the nonce root until runner destruction.
  self.close()
  observation=json.loads(run(self.as_user([self.programs/'aegis-research','engine-journal-status',self.journal,self.engine_digest]),env=self.env).stdout)
  if observation['attempts']!=1 or observation['unresolved_requests'] or observation['unfinished_attempts'] or observation['all_engine_writes_mediated'] or observation['cleanup_release_authorized']:raise RuntimeError('Independent plugin journal unconfirmed')
  self.finished=True
  self.proof={'schema_version':'1.0','separate_daemon':True,'raw_bootstrap_listener_removed':not self.bootstrap.exists(),'broker_has_raw_daemon_socket':False,'broker_has_daemon_socket_group':False,'end_to_end_tls_over_opaque_unix_relay':True,'relay_has_engine_credentials':False,'daemon_http2_setting':'GODEBUG=http2server=0','plugin_journal':observation,'controller_plugin_lease_binding_verified':False,'all_engine_writes_mediated':False,'cleanup_release_authorized':False,'public_beta':'NO-GO'}
  return self.proof
 def close(self):
  if sys.exc_info()[0] is not None:
   for name in ('bootstrap.log','authorized.log','plugin.log','relay.log'):
    path=self.root/name
    if path.is_file():print(name+': '+path.read_bytes()[-8000:].decode(errors='replace'),file=sys.stderr)
  try:
   for item in reversed(self.processes):self.process_stop(item)
  finally:
   try:self.daemon_stop()
   finally:
    if self.installed:run(['sudo','rm','--',self.spec]);self.installed=False
    for log in self.logs:
     if not log.closed:log.close()
