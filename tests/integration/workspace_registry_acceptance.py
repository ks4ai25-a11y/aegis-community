#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Fresh-only native registry provisioning; no engine or controller connection."""
import hashlib,json,os,pathlib,stat,subprocess,tempfile

ROOT=pathlib.Path(__file__).resolve().parents[2]
if not __debug__ or os.geteuid()<=0:raise SystemExit('Assertions and an unprivileged operator required')
checks=[]
def check(name):checks.append(name);print(name+': PASS',flush=True)
with tempfile.TemporaryDirectory(prefix='aegis-registry-proof-') as temporary:
 parent=pathlib.Path(temporary).resolve();binary=parent/'aegis-research'
 subprocess.run(['go','build','-trimpath','-o',str(binary),'./cmd/aegis-research'],cwd=ROOT/'alpha',check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
 env={**os.environ,'DOCKER_HOST':'unix://'+str(parent/'absent-engine.sock'),'AEGIS_SCANNER_ENGINE_TLS_DIR':str(parent/'absent-tls'),'AEGIS_SCANNER_SOCKET':str(parent/'absent-controller.sock')}
 def run(*args,ok=True):
  result=subprocess.run([binary,'workspace-registry-init',*args],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
  assert result.returncode==(0 if ok else 1),'unexpected registry-init outcome'
  return result
 refused=run(ok=False);assert not refused.stdout
 registry=parent/'registry';result=run(str(registry));out=json.loads(result.stdout)
 namespace=out.pop('registry_namespace_digest');assert namespace=='sha256:'+hashlib.sha256((registry/'.registry.json').read_bytes().rstrip(b'\n')).hexdigest()
 assert out=={'schema_version':'1.0','status':'initialized','controller_binding_verified':False,'active_workspace_leases_excluded':False,'cleanup_release_authorized':False}
 assert str(parent).encode() not in result.stdout
 assert stat.S_IMODE(registry.stat().st_mode)==0o700
 assert sorted(p.name for p in registry.iterdir())==['.registry-lock','.registry.json']
 lock=registry/'.registry-lock';before=lock.stat()
 assert stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode)==0o600 and before.st_size==0 and before.st_uid==os.geteuid() and before.st_nlink==1
 check('native_registry_init_provisions_private_lock_without_engine_or_controller')
 refused=run(str(registry),ok=False);assert not refused.stdout
 after=lock.stat();assert (after.st_dev,after.st_ino,after.st_mode,after.st_size)==(before.st_dev,before.st_ino,before.st_mode,before.st_size)
 check('existing_registry_is_not_reset_or_replaced')
 partial=parent/'partial';partial.mkdir(mode=0o700)
 run(str(partial),ok=False);assert list(partial.iterdir())==[]
 target=parent/'keep';target.mkdir(mode=0o700);marker=target/'sentinel';marker.write_bytes(b'owned synthetic state')
 link=parent/'linked';link.symlink_to(target,target_is_directory=True)
 run(str(link),ok=False);assert marker.read_bytes()==b'owned synthetic state'
 run('relative-registry',ok=False);assert not (ROOT/'relative-registry').exists()
 check('partial_linked_and_relative_namespaces_are_preserved_or_refused')
print('workspace_registry_checks: '+str(len(checks)),flush=True)
