# SPDX-License-Identifier: BUSL-1.1
"""Synthetic verifier/privacy tests; never start Docker or an engine daemon."""
import copy,hashlib,json,os,pathlib,re,sqlite3,stat,tempfile,types,unittest
from unittest import mock
from packaged_authorizer_fixture import AdmittedAuthorizer,write_private_admission_evidence
ROOT=pathlib.Path(__file__).resolve().parents[2]
def digest(value):return 'sha256:'+hashlib.sha256(json.dumps(value,separators=(',',':')).encode()).hexdigest()
def hashed(label):return 'sha256:'+hashlib.sha256(('synthetic '+label).encode()).hexdigest()
def wrapped(document):return {'digest':digest(document),'document':document}
class PackagedAdmission(unittest.TestCase):
 def fixture(self,parent,fault=''):
  path=parent/'snapshot.db';db=sqlite3.connect(path)
  bodies={}
  for file in ['store.go','migrations.go']:
   bodies.update(re.findall(r'const (\w+) = `([\s\S]*?)`',(ROOT/'controller/internal/store'/file).read_text()))
  source=(ROOT/'controller/internal/store/migrations.go').read_text();order=re.search(r'func migrationBodies\(\) \[\]string \{\s*return \[\]string\{([^}]+)\}',source).group(1)
  db.execute('PRAGMA foreign_keys=ON')
  for name in order.split(','):db.executescript(bodies[name.strip()])
  owner,authorizer,worker='synthetic-owner','synthetic-authorizer','synthetic-worker';job='0198e0d0-0000-7000-8000-000000000001';generation='a'*64;name='aegis-scan-'+'b'*32;native_id='c'*64;stamp='2026-10-17T00:00:00Z';deadline=1792195500
  binding={'owner_id':owner,'authorizer_id':authorizer,'engine_digest':hashed('engine'),'registry_digest':hashed('registry'),'policy_digest':hashed('policy'),'registry_namespace_digest':hashed('namespace'),'broker_binding_digest':hashed('broker'),'created_at':stamp};binding_digest=digest(binding)
  statements=[
   ("INSERT INTO owners VALUES(?,?,?)",(owner,'synthetic-password-hash',stamp)),
   ("INSERT INTO repositories VALUES(?,?,?,?,?,?)",('repository',owner,'app_demo','fixture',hashed('map'),stamp)),
   ("INSERT INTO application_maps VALUES(?,?,?,?)",('repository',hashed('map'),'{}',stamp)),
   ("INSERT INTO scanner_workers VALUES(?,?,?,'active',?,?)",(worker,owner,hashed('worker token'),deadline,stamp)),
   ("INSERT INTO scanner_authorizers VALUES(?,?,?,'active',?,?,?,?,?)",(authorizer,owner,hashed('authorizer token'),binding['engine_digest'],binding['registry_digest'],binding['policy_digest'],deadline,stamp)),
   ("INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires) VALUES(?,?,?,'app_demo',?,?,?,?,'{}','completed',?,?)",(job,owner,'repository',hashed('map'),hashed('lock'),hashed('request'),'synthetic-job-key',stamp,deadline)),
   ("INSERT INTO scanner_dispatch(slot,job,worker,token_hash,lease_until,deadline,state,guard_set_digest) VALUES(1,?,?,?,?,?,'cleanup_required',?)",(job,worker,hashed('lease'),deadline,deadline,hashed('guard'))),
   ("INSERT INTO scanner_mutation_bindings VALUES(?,?,?,?,?,?,?,?,?,'active')",(binding_digest,owner,authorizer,binding['engine_digest'],binding['registry_digest'],binding['policy_digest'],binding['registry_namespace_digest'],binding['broker_binding_digest'],stamp)),
  ]
  for sql,args in statements:db.execute(sql,args)
  db.execute("INSERT INTO settings VALUES('scanner_engine_broker_binding',?)",(json.dumps({'broker_binding_digest':binding['broker_binding_digest'],'document':{'worker_id':worker}}),))
  db.execute("INSERT INTO scanner_allocation_generations(job,id,owner,worker,binding_digest,lease_hash,deadline,guard_digest,created_at,state,closed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(job,generation,owner,worker,binding_digest,hashed('lease'),deadline,hashed('guard'),stamp,'open' if fault=='open-generation' else 'closed',stamp))
  db.execute("INSERT INTO scanner_workspaces VALUES(?,?,?,?,?,?,?,?)",(job,'bandit',owner,hashed('request'),'run-'+'d'*32,hashed('workspace'),'{}',stamp))
  records={};journal=parent/'journal'
  for op in ['create','start','remove']:
   request={'generation_id':generation,'job_id':job,'tool_id':'bandit','operation':op,'launch_digest':hashed('launch'),'descriptor_digest':hashed('descriptor '+op),'target_engine_id':'' if op=='create' else native_id}
   proposal={'intent_id':digest({'Domain':'aegis-scanner-mutation-intent-v1','Request':request,'Workspace':hashed('workspace'),'Container':name}),'request':request,'workspace_digest':hashed('workspace'),'container':name,'state':'pending'}
   pending=wrapped({'controller_intent':proposal,'schema_version':'1.0','attempt_digest':hashed('attempt'),'previous_digest':hashed('previous '+op),'operation':op,'container_id':request['target_engine_id'],'created_at':stamp})
   response=wrapped({'schema_version':'1.0','intent_digest':pending['digest'],'operation':op,'response_status':201 if op=='create' else 204,'container_id':native_id,'created_at':stamp})
   records[str(journal/name/(op+'.pending.json'))]=pending;records[str(journal/name/(op+'.response.json'))]=response
   if fault=='missing-remove' and op=='remove':continue
   db.execute("INSERT INTO scanner_mutation_intents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(proposal['intent_id'],generation,job,'bandit',op,hashed('launch'),hashed('workspace'),name,request['descriptor_digest'],request['target_engine_id'],stamp,'pending' if fault=='pending-start' and op=='start' else 'completed',response['digest'],response['document']['response_status'],native_id,stamp))
  seal=digest({'Domain':'aegis-controller-admitted-journal-v1','Policy':binding['policy_digest'],'Binding':binding_digest})
  records[str(journal/'policy.json')]=wrapped({'schema_version':'1.0','local_policy_digest':seal})
  if fault=='response-mismatch':records[str(journal/name/'remove.response.json')]['document']['response_status']=500
  if fault=='binding-mismatch':db.execute("UPDATE settings SET value=? WHERE key='scanner_engine_broker_binding'",(json.dumps({'broker_binding_digest':hashed('wrong broker'),'document':{'worker_id':worker}}),))
  db.commit();db.close();path.chmod(0o600)
  actor=object.__new__(AdmittedAuthorizer);actor.owner=owner;actor.authorizer=authorizer;actor.worker=worker;actor.digest=binding['engine_digest'];actor.registry_digest=binding['registry_digest'];actor.policy=binding['policy_digest'];actor.namespace=binding['registry_namespace_digest'];actor.journal=journal;actor.ledger_verified=False;actor.engine=types.SimpleNamespace(as_user=lambda args:args,env={})
  launch={'launch_digest':hashed('launch'),'document':{'plan':{'tool_id':'bandit','container_id':name},'guard_set_digest':hashed('guard')}}
  def read(args,**kwargs):return types.SimpleNamespace(stdout=json.dumps(records[str(args[-1])],separators=(',',':')).encode())
  return actor,path,job,[launch],read
 def test_matching_retained_records_verify_once(self):
  with tempfile.TemporaryDirectory() as temp:
   actor,path,job,launches,read=self.fixture(pathlib.Path(temp))
   with mock.patch('packaged_authorizer_fixture.run',side_effect=read):actor.verify_ledger(path,job,launches)
   self.assertTrue(actor.ledger_verified)
   with self.assertRaises(RuntimeError):actor.verify_ledger(path,job,launches)
 def test_incomplete_changed_or_open_state_never_confirms(self):
  for fault in ['missing-remove','pending-start','response-mismatch','binding-mismatch','open-generation']:
   with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temp:
    actor,path,job,launches,read=self.fixture(pathlib.Path(temp),fault)
    before=path.read_bytes()
    with mock.patch('packaged_authorizer_fixture.run',side_effect=read),self.assertRaises(AssertionError):actor.verify_ledger(path,job,launches)
    self.assertFalse(actor.ledger_verified);self.assertEqual(path.read_bytes(),before)
 def test_private_receipt_refuses_overwrite_links_and_public_parent(self):
  with tempfile.TemporaryDirectory(prefix='private-output-canary-') as temp:
   parent=pathlib.Path(temp).resolve();path=parent/'receipt.json';value={'private-runtime-canary':'retained privately'}
   write_private_admission_evidence(path,value)
   self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600);before=path.read_bytes()
   for target in [path,parent/'linked.json']:
    if target!=path:target.symlink_to(path)
    with self.assertRaises(RuntimeError) as error:write_private_admission_evidence(target,value)
    self.assertNotIn('canary',str(error.exception));self.assertEqual(path.read_bytes(),before)
   public=parent/'public';public.mkdir(mode=0o755)
   with self.assertRaises(RuntimeError):write_private_admission_evidence(public/'refused',value)
   self.assertFalse((public/'refused').exists())
 def mediation_actor(self,parent):
  root=parent/'aegis-packaged-engine-synthetic';(root/'data').mkdir(parents=True);(root/'dockerd.pid').write_text('4242')
  engine=types.SimpleNamespace(root=root,pidfile=root/'dockerd.pid',endpoint='https://127.0.0.1:23750',plugin_socket=root/'plugin/authz.sock',socket=str(root/'relay/docker.sock'),as_user=lambda args:list(args),env={},tls=root,client_dir=root/'broker-client',programs=root)
  actor=object.__new__(AdmittedAuthorizer);actor.engine=engine;actor.journal=root/'plugin/bound-journal';actor.mediation_verified=False
  return actor,root
 def listeners(self,root,tcp=None,unix=None):
  tcp=tcp if tcp is not None else ['LISTEN 0 4096 127.0.0.1:23750 0.0.0.0:* users:(("dockerd",pid=4242,fd=3))']
  unix=unix if unix is not None else ['u_str LISTEN 0 4096 '+str(root)+'/exec/containerd/containerd.sock 11 * 0 users:(("containerd",pid=4300,fd=5))','u_str LISTEN 0 4096 '+str(root)+'/relay/docker.sock 12 * 0 users:(("aegis-engine-re",pid=4400,fd=3))','u_str LISTEN 0 4096 /run/systemd/private 13 * 0 users:(("systemd",pid=1,fd=7))']
  def fake(args,**kwargs):
   if args[:2]==['sudo','ss']:return types.SimpleNamespace(stdout=('\n'.join(tcp if args[2]=='-Hltnp' else unix)+'\n').encode())
   raise AssertionError(args)
  return fake
 def test_single_tls_api_listener_and_private_internal_sockets(self):
  with tempfile.TemporaryDirectory() as temp:
   actor,root=self.mediation_actor(pathlib.Path(temp))
   unreachable=types.SimpleNamespace(returncode=1);reachable=types.SimpleNamespace(returncode=0)
   with mock.patch('packaged_authorizer_fixture.run',side_effect=self.listeners(root)),mock.patch('packaged_authorizer_fixture.subprocess.run',return_value=unreachable):actor.assert_single_api_listener()
   faults={
    'second-tcp':self.listeners(root,tcp=['LISTEN 0 4096 127.0.0.1:23750 0.0.0.0:* users:(("dockerd",pid=4242,fd=3))','LISTEN 0 4096 0.0.0.0:2375 0.0.0.0:* users:(("dockerd",pid=4242,fd=9))']),
    'no-tcp':self.listeners(root,tcp=[]),
    'raw-unix':self.listeners(root,unix=['u_str LISTEN 0 4096 /var/run/docker-raw.sock 11 * 0 users:(("dockerd",pid=4242,fd=4))']),
   }
   for fault,fake in faults.items():
    with self.subTest(fault=fault),mock.patch('packaged_authorizer_fixture.run',side_effect=fake),mock.patch('packaged_authorizer_fixture.subprocess.run',return_value=unreachable),self.assertRaises(RuntimeError):actor.assert_single_api_listener()
   with mock.patch('packaged_authorizer_fixture.run',side_effect=self.listeners(root)),mock.patch('packaged_authorizer_fixture.subprocess.run',return_value=reachable),self.assertRaises(RuntimeError):actor.assert_single_api_listener()
 def test_engine_state_digest_detects_engine_writes(self):
  import subprocess
  with tempfile.TemporaryDirectory() as temp:
   actor,root=self.mediation_actor(pathlib.Path(temp))
   def unprivileged(args,**kwargs):
    if args[0]!='sudo':raise AssertionError(args)
    return subprocess.run([str(a) for a in args[1:]],check=True,capture_output=True)
   data=root/'data'
   for path in ['containers','volumes','image/overlayfs/repositories','containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs','tmp']:(data/path).mkdir(parents=True)
   (data/'image/overlayfs/repositories/index.json').write_text('{}');(data/'containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/f').write_text('layer')
   with mock.patch('packaged_authorizer_fixture.run',side_effect=unprivileged):
    before=actor.engine_state();self.assertEqual(before,actor.engine_state())
    (data/'tmp/scratch').write_text('daemon scratch');self.assertEqual(before,actor.engine_state())
    for change in ['volumes/aegis-probe','containers/'+'e'*64]:
     (data/change).mkdir();self.assertNotEqual(before,actor.engine_state());(data/change).rmdir();self.assertEqual(before,actor.engine_state())
    (data/'image/overlayfs/repositories/index.json').write_text('{"aegis-probe":{}}');self.assertNotEqual(before,actor.engine_state())
    (data/'image/overlayfs/repositories/index.json').write_text('{}');(data/'containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/2').mkdir();self.assertNotEqual(before,actor.engine_state())
 def test_unadmitted_write_probe_requires_pass_and_unchanged_state(self):
  for fault in ['','probe-failed','state-changed','not-run']:
   with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temp:
    actor,root=self.mediation_actor(pathlib.Path(temp))
    for name in ['ca.pem','observer.pem','observer.key']:(root/name).write_text('synthetic')
    states=iter(['a'*64,'a'*64,'b'*64 if fault=='state-changed' else 'a'*64])
    output=b'=== RUN   TestRealPackagedEngineRefusesUnadmittedWrites\n'+(b'--- PASS: TestRealPackagedEngineRefusesUnadmittedWrites (1.00s)\n' if fault in ('','state-changed') else b'    packaged_mediation_real_test.go:91: volumes POST was not refused by the scanner authorizer for aegis-engine-broker (status 201)\n    /tmp/aegis-private-canary\n' if fault=='probe-failed' else b'')
    probe=types.SimpleNamespace(returncode=1 if fault=='probe-failed' else 0,stdout=output,stderr=b'')
    with mock.patch.object(AdmittedAuthorizer,'assert_single_api_listener'),mock.patch.object(AdmittedAuthorizer,'engine_state',side_effect=lambda:next(states)),mock.patch('packaged_authorizer_fixture.run'),mock.patch('packaged_authorizer_fixture.time.sleep'),mock.patch('packaged_authorizer_fixture.subprocess.run',return_value=probe),mock.patch('builtins.print') as printed:
     if fault:
      with self.assertRaises(RuntimeError):actor.probe_unadmitted_writes()
      self.assertFalse(actor.mediation_verified)
      self.assertNotIn('canary',repr(printed.call_args_list))
     else:
      actor.probe_unadmitted_writes();self.assertTrue(actor.mediation_verified)

class CrashRepairFixture(unittest.TestCase):
 """Synthetic checks for the ADR 057 crash repair acceptance helpers."""
 def test_held_requires_exactly_one_exact_slot(self):
  from packaged_crash_repair import held
  line='Held for cleanup: job 0198e0d0-0000-7000-8000-000000000001 generation '+'a'*64+' (job tool_error, finished 2026-10-17T00:00:00Z)\n'
  self.assertEqual(held(lambda *a:types.SimpleNamespace(stdout=line)),('0198e0d0-0000-7000-8000-000000000001','a'*64))
  for bad in ['',line+line,'No scanner slot is held.\n',line.replace('a'*64,'a'*63)]:
   with self.assertRaises(AssertionError):held(lambda *a,out=bad:types.SimpleNamespace(stdout=out))
