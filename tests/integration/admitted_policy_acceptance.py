#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Native policy provisioning input; no controller or engine is contacted."""
import hashlib,json,os,pathlib,tempfile
from engine_authz_acceptance import run,PrivateOperationError
ROOT=pathlib.Path(__file__).resolve().parents[2]
if not __debug__ or os.geteuid()<=0:raise SystemExit('Unprivileged operator and assertions required')
checks=[]
def check(name):checks.append(name);print(name+': PASS',flush=True)
with tempfile.TemporaryDirectory(prefix='aegis-admitted-input-') as temporary:
 parent=pathlib.Path(temporary).resolve();research=parent/'research';authz=parent/'authz'
 run(['go','build','-trimpath','-o',research,'./cmd/aegis-research'],cwd=ROOT/'alpha')
 run(['go','build','-trimpath','-o',authz,'./cmd/aegis-engine-authz'],cwd=ROOT/'alpha')
 registry=parent/'registry';namespace=json.loads(run([research,'workspace-registry-init',registry]).stdout)['registry_namespace_digest']
 engine='sha256:'+hashlib.sha256(b'synthetic-admitted-engine').hexdigest()
 registry_digest='sha256:'+hashlib.sha256(('aegis-scanner-workspace-registry-v1\n'+str(registry)+'\n'+str(os.geteuid())).encode()).hexdigest()
 journal=parent/'journal';run([authz,'init',journal,engine])
 args=[str(authz),'admitted-policy-input',str(parent/'native.sock'),str(journal),engine,str(registry),str(os.geteuid()),str(os.getegid()),str(ROOT/'tools/scanners.lock.json'),str(parent/'absent-controller.sock'),str(parent/'absent-authorizer.credential'),'synthetic-owner','synthetic-authorizer',registry_digest,namespace,'-']
 snapshot=lambda:{str(p.relative_to(parent)):hashlib.sha256(p.read_bytes()).hexdigest() for p in parent.rglob('*') if p.is_file()}
 before=snapshot();out=json.loads(run(args).stdout)
 digest=out.pop('policy_digest');assert digest.startswith('sha256:') and len(digest)==71
 assert out=={'schema_version':'1.0','controller_binding_verified':False,'engine_write_authorized':False,'cleanup_release_authorized':False}
 assert snapshot()==before and not (parent/'absent-authorizer.credential').exists() and not (parent/'native.sock').exists()
 assert json.loads(run(args).stdout)['policy_digest']==digest
 check('native_policy_input_is_stable_read_only_and_needs_no_live_credentials')
 changed=list(args);changed[12]='another-authorizer'
 assert json.loads(run(changed).stdout)['policy_digest']!=digest
 changed=list(args);changed[2]=str(parent/'another-listener.sock')
 # The plugin listener is transport, not serving authority, and is excluded.
 assert json.loads(run(changed).stdout)['policy_digest']==digest
 check('policy_scope_binds_authorizer_without_circular_selected_binding')
 for index,value in [(5,str(parent/'missing-root')),(6,'0'),(9,'relative-controller.sock'),(10,'relative-credential'),(12,'../invalid'),(13,'sha256:'+'f'*64),(14,'sha256:'+'e'*64)]:
  invalid=list(args);invalid[index]=value
  try:run(invalid)
  except PrivateOperationError as e:assert e.returncode==1
  else:raise AssertionError('invalid policy input accepted')
 assert snapshot()==before
 check('invalid_namespace_uid_scope_and_paths_are_refused_without_repair')
 serve=list(args);serve[1]='serve-admitted'
 try:run(serve)
 except PrivateOperationError as e:assert e.returncode==1
 else:raise AssertionError('missing authorizer credential accepted')
 assert snapshot()==before and not (parent/'native.sock').exists()
 check('serving_without_selected_authenticated_authority_never_opens_listener')
print('admitted_policy_checks: '+str(len(checks)),flush=True)
