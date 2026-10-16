#!/usr/bin/env python3
"""Opt-in authorization proof on a NEW daemon in a disposable GitHub runner.

Never runs on a workstation, never stops the runner's existing daemon, and never
mounts its socket or data root. All certificates, journals and state are private
nonce-owned fixtures; no raw engine socket survives the bootstrap stage.
"""
import hashlib,json,os,pathlib,platform,re,secrets,socket,ssl,subprocess,sys,tempfile,time,urllib.error,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[2]

def require_ci():
 if os.environ.get('AEGIS_REAL_ENGINE_AUTHZ_TEST')!='1' or os.environ.get('GITHUB_ACTIONS')!='true' or platform.system()!='Linux' or platform.machine() not in ('x86_64','amd64') or os.geteuid()<=0:
  raise RuntimeError('Explicit disposable GitHub Linux AMD64 CI fixture only')

class PrivateOperationError(subprocess.CalledProcessError):
 def __str__(self):return 'Private native fixture operation failed; diagnostic payload retained privately'

class PrivateOperationTimeout(subprocess.TimeoutExpired):
 def __str__(self):return 'Private native fixture operation exceeded its time bound'

def run(args,**kwargs):
 limit=kwargs.pop('timeout',180)
 if isinstance(limit,bool) or not isinstance(limit,(int,float)) or not 0<limit<=180:raise ValueError('Bounded native fixture timeout required')
 try:return subprocess.run([str(a) for a in args],check=True,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=limit,**kwargs)
 except subprocess.CalledProcessError as e:raise PrivateOperationError(e.returncode,e.cmd,output=e.output,stderr=e.stderr) from None
 except subprocess.TimeoutExpired as e:raise PrivateOperationTimeout(e.cmd,e.timeout,output=e.output,stderr=e.stderr) from None

def public_create_failure(line):
 # Strict full-line allowlist: arbitrary client output is never sanitized into
 # an apparently safe prefix. Reject appended paths, secrets and ANSI escapes.
 match=re.fullmatch(r'[ \t]*real_test.go:[0-9]+: (native create failed: connection reused=(?:true|false) request written=(?:true|false) intent recorded=(?:true|false) response recorded=(?:true|false))',line)
 return match[1] if match else None

def certificate(tlsdir,role,cn,server=False):
 key=tlsdir/(role+'.key');csr=tlsdir/(role+'.csr');crt=tlsdir/(role+'.pem');ext=tlsdir/(role+'.ext')
 run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',key])
 run(['openssl','req','-new','-key',key,'-subj','/CN='+cn,'-out',csr])
 ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage='+('serverAuth\nsubjectAltName=DNS:aegis-scanner-engine,IP:127.0.0.1\n' if server else 'clientAuth\n'))
 run(['openssl','x509','-req','-in',csr,'-CA',tlsdir/'ca.pem','-CAkey',tlsdir/'ca.key','-set_serial','0x'+secrets.token_hex(16),'-days','1','-sha256','-extfile',ext,'-out',crt])
 for p in (key,csr,crt,ext):p.chmod(0o600)

def main():
 require_ci();os.umask(0o077)
 engine=pathlib.Path(os.environ['AEGIS_CI_ENGINE_ROOT']).resolve(strict=True)
 prepared=json.loads((engine/'prepared.json').read_text());lock=json.loads((ROOT/'tools/ci-engine.lock.json').read_text())
 if prepared['scope']!='disposable_github_linux_amd64_ci_only' or prepared['archive_digest']!=lock['sha256'] or prepared['version']!=lock['version']:raise RuntimeError('Pinned CI engine receipt required')
 fixture=pathlib.Path(tempfile.mkdtemp(prefix='aegis-authz-ci-',dir='/tmp')).resolve(strict=True)
 for d in ('work','tls','plugin'):(fixture/d).mkdir(mode=0o700)
 tlsdir=fixture/'tls';uid=os.geteuid();gid=os.getegid();bootstrap=fixture/'bootstrap.sock';pidfile=fixture/'dockerd.pid'
 nonce=secrets.token_hex(12);plugin_name='aegis-authz-ci-'+nonce;spec=pathlib.Path('/etc/docker/plugins')/(plugin_name+'.spec')
 if spec.exists():raise RuntimeError('New plugin discovery name required')
 env=dict(os.environ);env['PATH']=str(engine/'bin')+':'+env['PATH']
 for k in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION'):env.pop(k,None)
 daemon=None;plugin=None;logs=[];installed=False
 def start(extra,label):
  log=(fixture/(label+'.log')).open('xb');logs.append(log)
  args=['sudo','env','PATH='+env['PATH'],'GODEBUG=http2server=0',str(engine/'bin/dockerd'),'--data-root='+str(fixture/'data'),'--exec-root='+str(fixture/'exec'),'--pidfile='+str(pidfile),'--containerd-namespace=aegis-authz-'+nonce,'--containerd-plugins-namespace=aegis-authz-plugins-'+nonce,'--bridge=none','--iptables=false','--ip6tables=false','--ip-forward=false','--ip-masq=false','--userland-proxy=false']+extra
  return subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=log,env=env,start_new_session=True)
 def stop(process):
  if process is None or process.poll() is not None:return
  value=pidfile.read_text().strip()
  if not re.fullmatch(r'[1-9][0-9]*',value):raise RuntimeError('Owned daemon PID unconfirmed')
  # The private root was allocated above and this exact pidfile is supplied only
  # to this daemon. Never enumerate or signal an ambient Docker process.
  run(['sudo','kill','-TERM',value]);process.wait(timeout=35)
 try:
  daemon=start(['--host=unix://'+str(bootstrap),'--group='+str(gid)],'bootstrap')
  info=None
  for _ in range(60):
   if daemon.poll() is not None:raise RuntimeError('Private bootstrap daemon exited')
   try:
    info=json.loads(run([engine/'bin/docker','--host','unix://'+str(bootstrap),'info','--format','{{json .}}'],env=env).stdout);break
   except (subprocess.CalledProcessError,json.JSONDecodeError):time.sleep(1)
  if info is None or info.get('OSType')!='linux' or not isinstance(info.get('ID'),str):raise RuntimeError('Private Linux engine unavailable')
  tool=next(t for t in json.loads((ROOT/'tools/scanners.lock.json').read_text())['tools'] if t['id']=='bandit')
  if not re.fullmatch(r'ghcr.io/pycqa/bandit/bandit@sha256:[0-9a-f]{64}',tool['image']):raise RuntimeError('Exact Bandit pin required')
  run([engine/'bin/docker','--host','unix://'+str(bootstrap),'pull',tool['image']],env=env)
  stop(daemon);daemon=None
  # The unauthenticated listener is removed before restarting the same private
  # data root with TLS verification and the native authorization plugin.
  if bootstrap.exists():raise RuntimeError('Bootstrap engine socket still exists')
  digest='sha256:'+hashlib.sha256(('aegis-authz-daemon-v1\n'+info['ID']).encode()).hexdigest()
  run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',tlsdir/'ca.key'])
  run(['openssl','req','-x509','-new','-key',tlsdir/'ca.key','-days','1','-sha256','-subj','/CN=Aegis isolated CI engine CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-out',tlsdir/'ca.pem'])
  for role,cn in [('server','aegis-scanner-engine'),('broker','aegis-engine-broker'),('observer','aegis-engine-observer'),('unknown','unapproved-client')]:certificate(tlsdir,role,cn,role=='server')
  for path in tlsdir.iterdir():path.chmod(0o600)
  journal=fixture/'plugin-journal';plugin_socket=fixture/'plugin'/'authz.sock'
  run([ROOT/'bin/aegis-engine-authz','init',journal,digest],env=env)
  log=(fixture/'plugin.log').open('xb');logs.append(log)
  plugin=subprocess.Popen([str(ROOT/'bin/aegis-engine-authz'),'serve',str(plugin_socket),str(journal),digest,str(fixture/'work'),str(uid),str(gid),str(ROOT/'tools/scanners.lock.json')],stdin=subprocess.DEVNULL,stdout=log,stderr=log,env=env,start_new_session=True)
  for _ in range(60):
   if plugin.poll() is not None:raise RuntimeError('Private authorization plugin exited')
   if plugin_socket.exists():break
   time.sleep(0.1)
  else:raise RuntimeError('Private authorization socket unavailable')
  local_spec=fixture/'plugin.spec';local_spec.write_text('unix://'+str(plugin_socket)+'\n')
  run(['sudo','mkdir','-p','/etc/docker/plugins']);run(['sudo','install','-m','600',local_spec,spec]);installed=True
  with socket.socket() as selected:selected.bind(('127.0.0.1',0));port=selected.getsockname()[1]
  endpoint='https://127.0.0.1:'+str(port)
  daemon=start(['--host=tcp://127.0.0.1:'+str(port),'--tlsverify','--tlscacert='+str(tlsdir/'ca.pem'),'--tlscert='+str(tlsdir/'server.pem'),'--tlskey='+str(tlsdir/'server.key'),'--authorization-plugin='+plugin_name],'authorized')
  context=ssl.create_default_context(cafile=str(tlsdir/'ca.pem'));context.minimum_version=ssl.TLSVersion.TLSv1_3;context.load_cert_chain(str(tlsdir/'observer.pem'),str(tlsdir/'observer.key'))
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
  actual=None
  for _ in range(60):
   if daemon.poll() is not None:raise RuntimeError('Authorized private daemon exited')
   try:
    with opener.open(endpoint+'/v1.55/info',timeout=3) as response:actual=json.load(response)
    break
   except (OSError,urllib.error.URLError):time.sleep(1)
  if not actual or actual.get('ID')!=info['ID']:raise RuntimeError('Original private engine identity unavailable')
  if bootstrap.exists():raise RuntimeError('Unexpected raw engine listener')
  # No certificate must fail TLS authentication before authorization policy.
  anonymous=ssl.create_default_context(cafile=str(tlsdir/'ca.pem'))
  try:
   urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=anonymous)).open(endpoint+'/v1.55/info',timeout=3)
  except (OSError,urllib.error.URLError):pass
  else:raise RuntimeError('Anonymous engine connection accepted')
  test_env=dict(env,AEGIS_AUTHZ_TEST_ROOT=str(fixture),AEGIS_AUTHZ_TEST_ENDPOINT=endpoint)
  result=subprocess.run(['go','test','-count=1','-run','^TestRealDaemonAuthorizationAndStaticScanner$','-v','./engineauthz'],cwd=ROOT/'alpha',env=test_env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
  # Complete client/daemon diagnostics stay private, including on failure.
  # Go errors and subprocess exceptions can include runtime paths/endpoints.
  (fixture/'client-test.log').write_bytes(result.stdout+b'\n'+result.stderr)
  if result.returncode or b'--- PASS: TestRealDaemonAuthorizationAndStaticScanner' not in result.stdout:
   for line in result.stdout.decode(errors='replace').splitlines():
    stage=public_create_failure(line)
    if stage:print(stage,file=sys.stderr)
   raise RuntimeError('Native engine authorization test failed or did not run')
  print('native_authorization_and_static_scanner: PASS',flush=True)
  # Prove plugin-unavailable fails closed on a harmless read. The daemon has
  # no bypass socket and the client has no alternate authority or admin cert.
  plugin.terminate();plugin.wait(timeout=10);plugin=None
  try:
   opener.open(endpoint+'/v1.55/info',timeout=45)
  except urllib.error.HTTPError as e:
   if e.code!=500:raise RuntimeError('Unexpected plugin-unavailable response')
  else:raise RuntimeError('Plugin failure did not close access')
  stop(daemon);daemon=None
  status=json.loads(run([ROOT/'bin/aegis-research','engine-journal-status',journal,digest],env=env).stdout)
  if status.get('attempts')!=1 or status.get('unfinished_attempts')!=0 or status.get('unresolved_requests')!=0 or any(status.get(k) is not False for k in ('controller_gate_binding_verified','all_engine_writes_mediated','cleanup_release_authorized')):raise RuntimeError('Independent plugin journal unconfirmed or inflated')
  acceptance=json.loads((fixture/'acceptance.json').read_text());acceptance['checks']+=['anonymous TLS refused','bootstrap raw listener removed','plugin unavailable fails closed','daemon stopped and plugin journal settled']
  acceptance['journal']=status;acceptance['ci_engine_version']=prepared['version'];acceptance['ci_engine_archive_digest']=prepared['archive_digest'];acceptance['publisher_signature_verified']=False
  output=ROOT/'docs/evidence/engine-authz-ci-acceptance.json';output.write_text(json.dumps(acceptance,indent=2)+'\n')
  for name in acceptance['checks']:print(name+': PASS',flush=True)
 finally:
  # Retain all private state on success/failure until this disposable runner is
  # destroyed. Cleanup never means deleting an unresolved journal namespace.
  try:stop(daemon)
  finally:
   if plugin is not None and plugin.poll() is None:plugin.terminate();plugin.wait(timeout=10)
   if installed:run(['sudo','rm','--',spec])
   for log in logs:log.close()
if __name__=='__main__':
 try:main()
 except Exception as error:
  # Avoid leaking certificate/key or credential bytes through subprocess error
  # output. The runner's private fixture logs are retained for local diagnosis.
  print('Isolated daemon authorization acceptance failed: '+type(error).__name__+'; private fixture retained',file=sys.stderr)
  raise SystemExit(1)
