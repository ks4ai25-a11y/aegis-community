# SPDX-License-Identifier: BUSL-1.1
"""ADR 057 sealed crash repair on the packaged admitted path (explicit CI only).

A test-only build of the authorizer exits right after the controller commits a
create admission and before any Allow reply. The slot stays held. The plugin
is then served in sealed quarantine, the dedicated daemon is restarted so the
quarantined plugin records a post-seal activation, the reconciler repairs the
pending create from an exact observation, the preserved workspace is
recovered, the slot is released, both journals settle from retained records,
admitted serving resumes and another real scan completes. Public output is
check names and statuses only.
"""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import json,os,re,secrets,shutil,time
from engine_authz_acceptance import run

HELD=re.compile(r'Held for cleanup: job ([0-9a-f-]{36}) generation ([0-9a-f]{64}) ')

def held(compose):
 out=compose('exec','-T','controller','aegisctl','scanner-reconciler','held').stdout
 found=HELD.findall(out)
 assert len(found)==1,'exactly one held slot expected'
 return found[0]

def wait_held(request,base,cookie,job,seconds=180):
 for _ in range(seconds):
  status,_=request(base,'/scans/'+job,cookie=cookie)
  if status['job']['state'] not in ('queued','running') and status['execution_admission']=='cleanup_required':return status
  time.sleep(1)
 raise RuntimeError('Crashed job did not close behind a held slot')

def repair_config(engine,bound,config_path):
 """Same private reconciler config plus the sealed plugin journal path."""
 document=json.loads(run(engine.as_user(['/usr/bin/cat',config_path]),env=engine.env).stdout)
 document['authorizer_journal']=str(bound.journal)
 staging=engine.root/'repair-config.json';staging.write_text(json.dumps(document));staging.chmod(0o600)
 target=os.path.join(os.path.dirname(config_path),'repair.json')
 run(['sudo','install','-o','10001','-g','10001','-m','600',str(staging),target]);staging.unlink()
 return target

def run_crash_repair(f):
 """f carries the acceptance script's private fixture handles."""
 engine=f.engine;bound=engine.bound;helper=f.helper;check=f.check
 reconcile=lambda args,mounts=None,success=True:helper(args,mounts=mounts or f.reconcile_mounts,extra=['--group-add',f.group],broker_tls=False,success=success)
 # Free the slot the two sequential scans left held, through the normal path.
 job,generation=held(f.compose);assert job==f.second_job
 assert json.loads(reconcile(['reconcile-cleanup',f.config_path,job,generation]).stdout)['dispatch_released'] is True

 third,_=f.request(f.base,'/scans',f.request_body,f.cookie,f.csrf,202,key=secrets.token_hex(16))
 bound.stop()
 fault=bound.serve_variant(bound.name+'-fault','serve-admitted',fault='exit-after-create-admission');bound.wait_ready(fault)
 result=f.raw(['start','--attach',f.worker_name],180,False);assert result.returncode!=0
 state=json.loads(f.raw(['inspect',fault]).stdout)[0]['State'];assert not state['Running'] and state['ExitCode']==86
 wait_held(f.request,f.base,f.cookie,third['job_id'])
 job,generation=held(f.compose);assert job==third['job_id']
 # The pending create blocks the ordinary release.
 assert reconcile(['reconcile-cleanup',f.config_path,job,generation],success=False).returncode!=0
 check('authorizer_killed_after_create_admission_keeps_slot_held')

 # Admitted serving cannot reopen the crashed journal; sealed quarantine can.
 assert bound.run_variant(bound.name+'-readmit','serve-admitted').returncode==1
 quarantine=bound.serve_variant(bound.name+'-quarantine','serve-quarantine');bound.wait_ready(quarantine)
 assert bound.journal_has('quarantine.1.json')
 # Reads through the old daemon reached the new plugin process without a
 # second activation: the daemon activates a legacy plugin once per process.
 assert not bound.journal_has('activation.1.json')
 journal_mount='type=bind,src='+str(bound.journal)+',dst='+str(bound.journal)+',readonly'
 repair_path=repair_config(engine,bound,f.config_path)
 repair_mounts=f.reconcile_mounts+[journal_mount]
 assert reconcile(['reconcile-repair',repair_path,job,generation],repair_mounts,success=False).returncode!=0
 check('crashed_journal_reopens_only_in_sealed_quarantine_and_repair_waits_for_fence')

 engine.daemon_restart('authorized-after-quarantine')
 assert bound.journal_has('activation.1.json')
 check('daemon_restart_records_post_seal_plugin_activation')

 repaired=json.loads(reconcile(['reconcile-repair',repair_path,job,generation],repair_mounts).stdout)
 assert repaired['schema_version']=='1.0' and repaired['cleanup_release_authorized'] is False and repaired['engine_writes_authorized'] is False and len(repaired['repairs'])==1
 resolution=repaired['repairs'][0]['resolution'];assert resolution['operation']=='create' and resolution['outcome']=='not_created' and resolution['engine_id']==''
 assert reconcile(['reconcile-repair',repair_path,job,generation],repair_mounts,success=False).returncode!=0
 status,_=f.request(f.base,'/scans/'+job,cookie=f.cookie);assert status['execution_admission']=='cleanup_required'
 check('pending_create_repaired_once_as_not_created_without_release')

 # The worker preserved its workspace; recover it only after the observer
 # reports the exact bound container absent (deferred for 180 s by design).
 registry=str(bound.registry)
 recover_mounts=[m.replace(',dst='+registry+',readonly',',dst='+registry) if m.startswith('type=bind,src='+registry+',') else m for m in f.reconcile_mounts]
 removed=0
 for _ in range(30):
  out=json.loads(reconcile(['recover-workspaces-observed',f.config_path],recover_mounts).stdout)
  removed+=out.get('removed',out.get('Removed',0))
  if removed:break
  time.sleep(10)
 assert removed==1
 released=json.loads(reconcile(['reconcile-cleanup',f.config_path,job,generation]).stdout)
 assert released['dispatch_released'] is True and len(released['request']['absent'])==1 and released['request']['absent'][0]['engine_id']==''
 check('repaired_generation_releases_after_exact_name_absence')

 assert bound.stop_variant(quarantine)['Running'] is False
 settled=json.loads(bound.run_variant(bound.name+'-settle','quarantine-settle').stdout)
 assert settled['settled'] is True and settled['journal']['unfinished_attempts']==0 and settled['cleanup_release_authorized'] is False
 broker=json.loads(helper(['engine-journal-settle','/run/scanner/worker.sock','/run/worker-credential/worker.credential',f.owner,'/opt/aegis',str(f.work_root/'engine-journal'),f.engine_digest],mounts=f.mounts).stdout)
 assert broker['unfinished_attempts']==0 and broker['unresolved_requests']==0
 bound.restart_admitted()
 check('plugin_and_broker_journals_settle_from_retained_records')

 fourth,_=f.request(f.base,'/scans',f.request_body,f.cookie,f.csrf,202,key=secrets.token_hex(16))
 result=f.raw(['start','--attach',f.worker_name],120,False);assert result.returncode==0
 outcome=json.loads(result.stdout);assert outcome['job_id']==fourth['job_id'] and outcome['state']=='completed'
 status,_=f.request(f.base,'/scans/'+fourth['job_id'],cookie=f.cookie);assert status['execution_admission']=='cleanup_required'
 check('next_real_scan_completes_after_crash_repair_and_is_held_again')
 return {'crashed_jobs':1,'repaired_intents':1,'outcome':'not_created','daemon_restarted':True,'next_scan_completed':True}
