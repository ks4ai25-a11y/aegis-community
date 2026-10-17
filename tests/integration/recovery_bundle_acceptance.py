#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Native recovery CLI proof using private synthetic state; no live services."""
import datetime,hashlib,json,os,pathlib,secrets,sqlite3,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
if not __debug__:raise SystemExit('Recovery proof requires assertions enabled')
checks=[]
def check(name):checks.append({'id':name,'result':'PASS'});print(name+': PASS',flush=True)
with tempfile.TemporaryDirectory(prefix='aegis-recovery-native-') as temporary:
 parent=pathlib.Path(temporary).resolve();binary=parent/'aegisctl';source=parent/'source';source.mkdir(mode=0o700)
 subprocess.run(['go','build','-trimpath','-o',str(binary),'./cmd/aegisctl'],cwd=ROOT/'controller',check=True,capture_output=True,timeout=180)
 env={**os.environ,'AEGIS_DATA':str(source),'GATEWAY_POLICY_ROOT':str(source),'AEGIS_SCANNER_LOCK':str(ROOT/'tools/scanners.lock.json')}
 def run(*args,success=True):
  result=subprocess.run([str(binary),*args],env=env,text=True,capture_output=True,timeout=70)
  assert result.returncode==(0 if success else 1),'unexpected recovery CLI exit'
  return result
 run('init')
 with sqlite3.connect(source/'aegis.db') as database:
  database.execute("INSERT INTO owners VALUES('synthetic-owner','fixture-password-hash','2026-10-15T00:00:00Z')")
  database.execute("INSERT INTO sessions VALUES('synthetic-old-session','synthetic-owner','csrf',1,1,2147483647)")
  database.execute("INSERT INTO scanner_workers VALUES('worker','synthetic-owner','synthetic-worker-hash','active',2147483647,'2026-10-15T00:00:00Z')")
  database.execute("INSERT INTO settings VALUES('recovery-fixture-marker','preserved-private-value')")
  database.commit();database.execute('PRAGMA wal_checkpoint(TRUNCATE)')
 original=hashlib.sha256((source/'aegis.db').read_bytes()).hexdigest()
 bundle=parent/'bundle';created=json.loads(run('backup','bundle',str(bundle),'--json').stdout)
 assert created['status']=='bundle_created' and created['integrity_verified'] is True
 assert created['application_restore_verified'] is False and created['publisher_signature_verified'] is False
 assert hashlib.sha256((source/'aegis.db').read_bytes()).hexdigest()==original
 check('bundle_creation_leaves_source_database_unchanged')
 manifest=json.loads((bundle/'manifest.json').read_text())
 assert created['bundle_digest']==manifest['bundle_digest']
 assert manifest['document']['policy_digest']==created['policy_digest']
 assert manifest['document']['scanner_lock']['sha256']==created['tool_lock_digest']
 for filename in ('manifest.json','state.db','active.Caddyfile','scanners.lock.json','.lock'):assert (bundle/filename).stat().st_mode&0o777==0o600
 check('private_bundle_binds_database_policy_gateway_and_tool_lock')
 verified=json.loads(run('backup','verify',str(bundle),'--json').stdout)
 assert verified['status']=='bundle_verified' and verified['bundle_digest']==created['bundle_digest']
 check('verification_accepts_exact_trusted_profile')
 destination=parent/'restored'
 assert not run('backup','restore',str(bundle),str(destination),'--confirm','sha256:'+'0'*64,'--json',success=False).stdout
 assert not destination.exists()
 check('wrong_confirmation_never_allocates_restore_destination')
 restored=json.loads(run('backup','restore',str(bundle),str(destination),'--confirm',created['bundle_digest'],'--json').stdout)
 assert restored['status']=='restored_offline' and restored['restored_authorities_invalidated'] is True
 assert restored['scanner_cleanup_holds_preserved'] is True
 assert restored['live_activated'] is False and restored['application_restore_verified'] is False
 artifact=destination/'data/aegis.db'
 assert restored['restored_database_digest']=='sha256:'+hashlib.sha256(artifact.read_bytes()).hexdigest()
 assert not (destination/'data/.restore-pending').exists() and (destination/'data/.restore-complete.json').is_file()
 with sqlite3.connect(artifact.as_uri()+'?mode=ro&immutable=1',uri=True) as database:
  assert database.execute('SELECT count(*) FROM sessions').fetchone()==(0,)
  assert database.execute("SELECT count(*) FROM scanner_workers WHERE state='active'").fetchone()==(0,)
  assert database.execute("SELECT value FROM settings WHERE key='recovery-fixture-marker'").fetchone()==('preserved-private-value',)
 check('offline_restore_invalidates_access_preserves_history_and_hashes_installed_state')
 assert (destination/'gateway/active.Caddyfile').read_bytes()==(bundle/'active.Caddyfile').read_bytes()
 assert (destination/'tools/scanners.lock.json').read_bytes()==(bundle/'scanners.lock.json').read_bytes()
 check('offline_restore_preserves_matching_gateway_and_tool_bytes')
 assert not run('backup','restore',str(bundle),str(destination),'--confirm',created['bundle_digest'],'--json',success=False).stdout
 check('existing_destination_is_never_overwritten')
 assert json.loads(run('backup','verify',str(bundle),'--json').stdout)['bundle_digest']==created['bundle_digest']
 check('restore_never_modifies_original_bundle')
 unknown=parent/'unknown-lock.json';unknown.write_bytes((ROOT/'tools/scanners.lock.json').read_bytes()+b'\n');unknown.chmod(0o600)
 original_lock=env['AEGIS_SCANNER_LOCK'];env['AEGIS_SCANNER_LOCK']=str(unknown)
 assert not run('backup','verify',str(bundle),'--json',success=False).stdout
 env['AEGIS_SCANNER_LOCK']=original_lock
 check('a_different_trusted_tool_lock_refuses_recovery')
 (bundle/'active.Caddyfile').write_bytes(b'changed')
 assert not run('backup','verify',str(bundle),'--json',success=False).stdout
 check('changed_bundle_configuration_is_rejected')
 report={'schema_version':'1.0','status':'PASS','scope':'native synthetic bundle creation, verification and confirmed offline restore; no live application activation','recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':checks,'receipts':[created,verified,restored],'manifest':manifest,'binary_digest':'sha256:'+hashlib.sha256(binary.read_bytes()).hexdigest()}
 evidence=os.environ.get('AEGIS_RECOVERY_EVIDENCE')
 if evidence:pathlib.Path(evidence).write_text(json.dumps(report,indent=2)+'\n')
 print('native_recovery_checks: '+str(len(checks)),flush=True)
