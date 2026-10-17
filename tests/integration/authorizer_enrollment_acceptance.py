#!/usr/bin/env python3
"""Compiled operator CLI, using only fresh private synthetic controller state."""
import hashlib,os,pathlib,sqlite3,subprocess,tempfile

ROOT=pathlib.Path(__file__).resolve().parents[2]
if not __debug__ or os.geteuid()<=0:raise SystemExit('Assertions and an unprivileged operator required')
checks=[]
def check(name):checks.append(name);print(name+': PASS',flush=True)
with tempfile.TemporaryDirectory(prefix='aegis-authorizer-proof-') as temporary:
 parent=pathlib.Path(temporary).resolve();binary=parent/'aegisctl';data=parent/'data';data.mkdir(mode=0o700)
 subprocess.run(['go','build','-trimpath','-o',str(binary),'./cmd/aegisctl'],cwd=ROOT/'controller',check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
 env={**os.environ,'AEGIS_DATA':str(data),'GATEWAY_POLICY_ROOT':str(data),'AEGIS_SCANNER_SOCKET':str(parent/'absent.sock')}
 def run(*args,ok=True):
  r=subprocess.run([binary,*args],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
  assert r.returncode==(0 if ok else 1),'unexpected operator CLI outcome'
  return r
 run('scanner-authorizer','enroll',ok=False)
 assert not (data/'aegis.db').exists()
 check('invalid_authorizer_arguments_create_no_state')
 run('init')
 digest=lambda b:'sha256:'+hashlib.sha256(b).hexdigest()
 engine,registry,policy=[digest(x) for x in (b'synthetic-engine',b'synthetic-registry',b'synthetic-policy')]
 dbpath=data/'aegis.db'
 with sqlite3.connect(dbpath) as db:
  db.execute("INSERT INTO owners VALUES('fixture-owner','synthetic-not-a-password','2026-10-16T00:00:00Z')")
  db.execute("INSERT INTO settings VALUES('repository_mount_owner','fixture-owner')")
  db.execute("INSERT INTO repositories VALUES('fixture-repo','fixture-owner','app_demo','fixture','synthetic-map','2026-10-16T00:00:00Z')")
 credential=parent/'authorizer.credential'
 result=run('scanner-authorizer','enroll','gate-a','1',engine,registry,policy,str(credential))
 token=credential.read_bytes();assert len(token)==65 and credential.stat().st_mode&0o777==0o600
 assert b'native admission requires separate policy selection' in result.stdout and token.strip() not in result.stdout+result.stderr
 check('compiled_authorizer_enrollment_delivers_private_credential_only')
 with sqlite3.connect(dbpath) as db:
  row=db.execute('SELECT id,owner,state,engine_digest,registry_digest,policy_digest,token_hash FROM scanner_authorizers').fetchone()
  assert row[:6]==('gate-a','fixture-owner','active',engine,registry,policy)
  assert row[6]==digest(b'aegis-scanner-engine-authorizer-v1\x00'+token.strip())
  assert db.execute('SELECT count(*) FROM migrations WHERE version=14').fetchone()==(1,)  # authorizer migration retained across later upgrades
  assert db.execute('SELECT count(*) FROM scanner_workers').fetchone()==(0,)
  assert db.execute('SELECT count(*) FROM scanner_verifiers').fetchone()==(0,)
  assert db.execute('SELECT count(*) FROM scanner_dispatch').fetchone()==(0,)
  assert token.strip().decode() not in str(db.execute('SELECT document FROM audit').fetchall())
 check('enrollment_binds_exact_scope_without_worker_observer_or_dispatch_authority')
 run('scanner-authorizer','enroll','gate-a','1',engine,registry,policy,str(credential),ok=False)
 assert credential.read_bytes()==token
 other=parent/'other.credential'
 run('scanner-authorizer','enroll','gate-b','1',engine,registry,policy,str(other),ok=False)
 assert not other.exists()
 run('scanner-authorizer','enroll','gate-b','1',engine,registry,'invalid-policy',str(other),ok=False)
 assert not other.exists()
 refused=run('scanner-authorizer','probe',str(credential),ok=False)
 assert token.strip() not in refused.stdout+refused.stderr
 check('occupied_path_active_budget_invalid_policy_and_unavailable_probe_refused')
 namespace=digest(b'synthetic-approved-protocol2-namespace')
 run('scanner-authorizer','bind','gate-a',namespace,ok=False)
 run('scanner-engine','bind',engine,registry)
 run('scanner-engine','bind-journal',digest(b'synthetic-journal-root'),digest(b'synthetic-journal-namespace'))
 worker_credential=parent/'worker.credential'
 run('scanner-worker','enroll','worker-a','1',str(worker_credential))
 run('scanner-engine','bind-broker','worker-a')
 bound=run('scanner-authorizer','bind','gate-a',namespace)
 assert token.strip() not in bound.stdout+bound.stderr
 run('scanner-authorizer','bind','gate-a',namespace)
 run('scanner-authorizer','bind','gate-a',digest(b'replacement-namespace'),ok=False)
 with sqlite3.connect(dbpath) as db:
  assert db.execute('SELECT authorizer,engine_digest,registry_digest,policy_digest,namespace_digest,state FROM scanner_mutation_bindings').fetchone()==('gate-a',engine,registry,policy,namespace,'active')
  assert db.execute('SELECT count(*) FROM scanner_allocation_generations').fetchone()==(0,)
  assert db.execute('SELECT count(*) FROM scanner_dispatch').fetchone()==(0,)
 check('compiled_selection_binds_exact_scope_without_adopting_a_dispatch')
 run('scanner-authorizer','revoke','gate-a');run('scanner-authorizer','revoke','gate-a')
 with sqlite3.connect(dbpath) as db:
  assert db.execute("SELECT state FROM scanner_authorizers WHERE id='gate-a'").fetchone()==('revoked',)
  assert db.execute("SELECT state FROM scanner_mutation_bindings WHERE authorizer='gate-a'").fetchone()==('revoked',)
  assert db.execute("SELECT count(*) FROM audit WHERE document LIKE '%scanner.authorizer_revoke%'").fetchone()==(1,)
 run('audit','verify')
 check('revocation_is_retained_idempotent_and_audited')
print('authorizer_enrollment_checks: '+str(len(checks)),flush=True)
