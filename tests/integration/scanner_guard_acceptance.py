#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Scanner guard failure tests. Only created Aegis-labelled containers are touched."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import json,os,pathlib,shutil,subprocess,tempfile,time,secrets
ROOT=pathlib.Path(__file__).resolve().parents[2]
BINARY=ROOT/'bin/aegis-research'
checks=[]
report={'schema_version':'1.0','scope':'trusted-static-fixture-guard-failures','checks':checks,'started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
def check(name,detail):checks.append({'id':name,'result':'PASS','detail':detail});print(name+': PASS',flush=True)
try:
 env={**os.environ,'AEGIS_SCAN_MAX_SECONDS':'1'}
 run=subprocess.run([str(BINARY),'scan-offline','semgrep_ce',str(ROOT/'alpha/fixtures/scanners/vulnerable'),str(ROOT)],env=env,capture_output=True,timeout=20)
 receipt=json.loads(run.stdout)
 assert run.returncode==1 and receipt['exit_code']==124 and receipt['status']=='tool_error' and receipt['cleanup_state']=='complete',receipt
 assert not receipt['result']['findings'] and any(d['code']=='SCANNER_DEADLINE' for d in receipt['result']['diagnostics'])
 check('guard_deadline_never_returns_completed_zero_findings',{'exit_code':receipt['exit_code'],'duration_ms':receipt['duration_ms'],'guard_binary_digest':receipt['guard_binary_digest']})
 # Change an input byte under a trusted test mount: the PID-1 verifier must
 # reject it before the scanner can produce any completed output.
 with tempfile.TemporaryDirectory(prefix='aegis-guard-tamper-') as tmp:
  base=pathlib.Path(tmp).resolve();src=base/'source';guard=base/'guard';src.mkdir();guard.mkdir()
  for original in (ROOT/'alpha/fixtures/scanners/vulnerable').iterdir():
   if original.is_file():shutil.copyfile(original,src/original.name)
  (src/'query.py').write_text('tampered synthetic source')
  architecture=subprocess.check_output(['docker','info','--format','{{.Architecture}}']).decode().strip()
  architecture={'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}[architecture]
  shutil.copyfile(ROOT/'bin'/('scanner-guard-linux-'+architecture),guard/'scanner-guard');(guard/'scanner-guard').chmod(0o500)
  (guard/'input-manifest.json').write_text(json.dumps(receipt['source_snapshot']))
  image='semgrep/semgrep@'+receipt['tool_image_digest']
  name='aegis-guard-tamper-'+secrets.token_hex(12)
  try:
   denied=subprocess.run(['docker','run','--rm','--name',name,'--pull=never','--network=none','--read-only','--user='+str(os.getuid())+':'+str(os.getgid()),'--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=768m','--memory-swap=768m','--cpus=1','--log-driver=none','--mount','type=bind,src='+str(src)+',dst=/src,readonly','--mount','type=bind,src='+str(guard)+',dst=/aegis,readonly','--entrypoint','/aegis/scanner-guard',image,'semgrep_ce','10'],capture_output=True,timeout=15)
   assert denied.returncode==125 and not denied.stdout,(denied.returncode,denied.stderr[:512])
   check('actual_container_input_tamper_refused_before_scanner',{'guard_exit_code':125,'scanner_output_bytes':len(denied.stdout)})
  finally:subprocess.run(['docker','rm','--force',name],capture_output=True,timeout=10)
 # Keep a scanner busy past the deadline while deliberately killing only its
 # own host CLI. The guard must still end the container independently.
 with tempfile.TemporaryDirectory(prefix='aegis-guard-input-') as tmp:
  src=pathlib.Path(tmp).resolve()
  line='db.execute("SELECT * FROM products WHERE name=\'" + name + "\'")\n'
  for i in range(32):(src/f'query_{i}.py').write_text(line*14000)
  scratch=pathlib.Path(tempfile.mkdtemp(prefix='aegis-recovery-test-')).resolve()
  env={**os.environ,'AEGIS_SCAN_MAX_SECONDS':'8','TMPDIR':str(scratch)}
  cli=subprocess.Popen([str(BINARY),'scan-offline','semgrep_ce',str(src),str(ROOT)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  container=None;mounts=[];waiter=None
  try:
   until=time.monotonic()+20
   while time.monotonic()<until:
    ids=subprocess.check_output(['docker','ps','--filter','label=io.aegis.operator_pid='+str(cli.pid),'--format','{{.ID}}']).decode().split()
    if ids:assert len(ids)==1;container=ids[0];break
    if cli.poll() is not None:
     output,error=cli.communicate();raise AssertionError('CLI stopped before guarded container was observed: '+error.decode(errors='replace')[:500]+' '+output.decode(errors='replace')[:500])
    time.sleep(.1)
   assert container,'Guarded scanner container did not start'
   info=json.loads(subprocess.check_output(['docker','inspect',container]))[0]
   assert info['State']['Running'] and info['Config']['Entrypoint']==['/aegis/scanner-guard']
   assert info['HostConfig']['NetworkMode']=='none' and info['HostConfig']['ReadonlyRootfs']
   assert info['HostConfig']['LogConfig']['Type']=='none'
   assert info['HostConfig']['PidsLimit']==128 and info['HostConfig']['Memory']==768*1024*1024
   assert info['HostConfig']['MemorySwap']==768*1024*1024 and info['HostConfig']['NanoCpus']==1000000000
   assert 'no-new-privileges' in ' '.join(info['HostConfig']['SecurityOpt'])
   assert all(m['RW'] is False for m in info['Mounts'])
   assert all('docker.sock' not in m['Destination'] for m in info['Mounts'])
   mounts=[pathlib.Path(m['Source']).resolve() for m in info['Mounts'] if m['Destination'] in ['/src','/rules','/aegis']]
   active=subprocess.run([str(BINARY),'recover-workspaces'],env=env,capture_output=True,timeout=10)
   assert active.returncode==0 and json.loads(active.stdout)['active']==1
   check('recovery_preserves_live_kernel_lease',{'active':1})
   second=subprocess.run([str(BINARY),'scan-offline','syft',str(ROOT/'alpha/fixtures/scanners/safe'),str(ROOT)],env=env,capture_output=True,timeout=10)
   assert second.returncode!=0 and not second.stdout and b'registry occupied' in second.stderr
   check('second_scanner_cli_refused_while_first_runs',{'normalized_receipts':0})

   waiter=subprocess.Popen(['docker','wait',container],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   time.sleep(.2);started=time.monotonic();cli.kill();cli.communicate(timeout=5)
   code,error=waiter.communicate(timeout=15)
   assert waiter.returncode==0 and code.strip()==b'124',(code,error)
   until_removed=time.monotonic()+5
   while True:
    remaining=subprocess.check_output(['docker','ps','--all','--filter','label=io.aegis.scan='+info['Name'].lstrip('/'),'--format','{{.ID}}']).strip()
    if not remaining:break
    assert time.monotonic()<until_removed,'Guarded container was not removed after terminal wait'
    time.sleep(.1)
   check('container_guard_survives_host_cli_sigkill',{'guard_exit_code':124,'elapsed_after_cli_kill_seconds':round(time.monotonic()-started,3),'network_profile':'none','read_only_mounts':True,'log_driver':'none'})
  finally:
   if cli.poll() is None:cli.kill();cli.communicate(timeout=5)
   if waiter and waiter.poll() is None:waiter.kill();waiter.communicate(timeout=5)
   if container:subprocess.run(['docker','rm','--force',container],capture_output=True,timeout=10)
   # Recovery is tested in an isolated, test-owned registry. Age only that
   # orphan's journal to exercise the 180-second grace without a long sleep.
   if mounts:
    session=mounts[0].parent
    assert all(p.parent==session for p in mounts)
    assert session.parent==scratch/('aegis-scanner-workspaces-'+str(os.getuid()))
    assert session.name.startswith('run-') and not session.is_symlink()
    deferred=subprocess.run([str(BINARY),'recover-workspaces'],env=env,capture_output=True,timeout=10)
    assert deferred.returncode==0 and json.loads(deferred.stdout)['deferred']==1
    orphan_second=subprocess.run([str(BINARY),'scan-offline','syft',str(ROOT/'alpha/fixtures/scanners/safe'),str(ROOT)],env=env,capture_output=True,timeout=10)
    assert orphan_second.returncode!=0 and not orphan_second.stdout and b'registry occupied' in orphan_second.stderr
    check('unrecovered_orphan_blocks_new_cli_scan',{'normalized_receipts':0})

    journal=session/'journal.json';data=json.loads(journal.read_text());data['created_unix']=int(time.time())-240;journal.write_text(json.dumps(data))
    original_engine=data['engine_digest'];data['engine_digest']='sha256:'+'0'*64;journal.write_text(json.dumps(data))
    wrong_engine=subprocess.run([str(BINARY),'recover-workspaces'],env=env,capture_output=True,timeout=10)
    assert wrong_engine.returncode!=0 and session.exists()
    check('workspace_recovery_refuses_engine_identity_mismatch',{'workspace_preserved':True})
    data['engine_digest']=original_engine;journal.write_text(json.dumps(data))
    recovered=subprocess.run([str(BINARY),'recover-workspaces'],env=env,capture_output=True,timeout=10)
    assert recovered.returncode==0 and json.loads(recovered.stdout)['removed']==1 and not session.exists(),recovered.stderr
    check('journalled_host_workspace_recovery_after_sigkill',{'workspace_count':len(mounts),'removed_sessions':1,'grace_age_simulated_in_test':True})
   shutil.rmtree(scratch)
 report['overall']='PASS'
except Exception as e:
 report['overall']='FAIL';report['error']=str(e)[:1800];raise
finally:
 report['completed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
 report['limitations']=['Local ARM64 Docker Desktop and trusted inert inputs only.','Operator recovery is explicit; durable scanner job orchestration and automatic recovery remain required.','No arbitrary user-code execution, VM boundary or independent isolation review claim.']
 (ROOT/'docs/evidence/scanner-guard-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
