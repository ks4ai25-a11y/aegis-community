# SPDX-License-Identifier: BUSL-1.1
"""Nonce-owned broker/client extension of the isolated packaged worker proof."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import json,re,time
class BrokerFixture:
 def __init__(self,raw,compose,helper,check,helpers,project,nonce,worker_id,owner,group,mounts,root_mount,work_root,secret_volume,arguments,engine_fixture=None):
  self.engine_fixture=engine_fixture
  self.raw,self.compose,self.helper,self.check,self.helpers=raw,compose,helper,check,helpers
  self.project,self.nonce,self.group,self.mounts,self.arguments=project,nonce,group,mounts,arguments
  self.volumes=[project+'-dispatch-credential',project+'-broker-socket'];self.broker_name=project+'-broker'
  self.images={name:raw(['image','inspect','aegis-community/'+name+':0.1.0-alpha.1','--format','{{.Id}}']).stdout.strip() for name in ['scanner-broker','scanner-dispatch']}
  assert all(re.fullmatch(r'sha256:[0-9a-f]{64}',value) for value in self.images.values())
  for volume in self.volumes:
   raw(['volume','create','--label','io.aegis.worker-proof='+nonce,volume]);assert json.loads(raw(['volume','inspect',volume]).stdout)[0]['Labels']['io.aegis.worker-proof']==nonce
  self.client_mounts=['type=volume,src='+self.volumes[1]+',dst=/run/scan-broker,readonly','type=volume,src='+self.volumes[0]+',dst=/run/dispatch-credential,readonly']
  name=project+'-dispatch-enroll';helpers.append(name)
  raw(['run','--rm','--pull=never','--name',name,'--label','io.aegis.worker-proof='+nonce,'--network','none','--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--mount','type=volume,src='+self.volumes[0]+',dst=/run/dispatch-credential',self.images['scanner-dispatch'],'enroll','/run/dispatch-credential/client.credential'])
  self.binding=json.loads(compose('exec','-T','controller','aegisctl','scanner-engine','bind-broker',worker_id).stdout)
  assert self.binding['document']['worker_id']==worker_id and self.binding['document']['owner_id']==owner
  assert json.loads(compose('exec','-T','controller','aegisctl','scanner-engine','bind-broker',worker_id).stdout)==self.binding
  other='other-'+nonce;compose('run','--rm','--no-deps','--volume',secret_volume+':/run/scanner','--entrypoint','aegisctl','init','scanner-worker','enroll',other,'10','/run/scanner/other.credential')
  assert compose('exec','-T','controller','aegisctl','scanner-engine','bind-broker',other,success=False).returncode!=0
  altered=list(arguments);altered[2]='/run/worker-credential/other.credential';denied=helper(altered,mounts=mounts,extra=['--group-add',group,'--env','TMPDIR='+str(work_root)],success=False);assert denied.returncode!=0 and json.loads(denied.stdout)['state']=='not_claimed'
  altered[2]='/run/dispatch-credential/client.credential';wrong_role=helper(altered,mounts=[m for m in mounts if 'dst=/run/worker-credential' not in m]+[self.client_mounts[1]],extra=['--group-add',group,'--env','TMPDIR='+str(work_root)],success=False);assert wrong_role.returncode!=0 and json.loads(wrong_role.stdout)['state']=='not_claimed'
  check('controller_bound_broker_refuses_other_workers_and_dispatch_credential_role')
  helpers.append(self.broker_name)
  command=['create','--pull=never','--name',self.broker_name,'--label','io.aegis.worker-proof='+nonce,'--network','none','--read-only','--user','10001:10001','--group-add',group,'--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--pids-limit','128','--cpus','1','--log-driver','none','--env','TMPDIR='+str(work_root)]
  if engine_fixture is not None:
   command.remove('--group-add');command.remove(group);command+=['--env','AEGIS_SCANNER_ENGINE_TLS_DIR=/run/engine-tls','--mount','type=bind,src='+str(engine_fixture.client_dir)+',dst=/run/engine-tls,readonly']
  for mount in mounts+[self.client_mounts[1],'type=volume,src='+self.volumes[1]+',dst=/run/scan-broker']:command+=['--mount',mount]
  command+=[self.images['scanner-broker'],'/run/scan-broker/dispatch.sock','/run/dispatch-credential/client.credential','/run/scanner/worker.sock','/run/worker-credential/worker.credential',owner,worker_id,'/opt/aegis','/opt/aegis/repositories',str(work_root/'engine-journal')]
  raw(command);raw(['start',self.broker_name])
  for _ in range(40):
   if helper(['test','-S','/run/scan-broker/dispatch.sock'],entry='/bin/busybox',mounts=[self.client_mounts[0]],success=False).returncode==0:break
   time.sleep(.1)
  else:raise RuntimeError('Owned broker did not expose its private socket')
  config=json.loads(raw(['inspect',self.broker_name]).stdout)[0];host=config['HostConfig']
  assert config['Config']['Entrypoint']==['/aegis-scanner-broker'] and config['Config']['User']=='10001:10001'
  assert host['NetworkMode']=='none' and host['ReadonlyRootfs'] and host['CapDrop']==['ALL'] and not host['Privileged'] and (not host['GroupAdd'] if engine_fixture is not None else host['GroupAdd']==[group]) and host['RestartPolicy']['Name']=='no'

  if engine_fixture is not None:
   actual={m['Destination']:m for m in config['Mounts']};assert actual['/run/engine/docker.sock']['Source']==engine_fixture.socket and not actual['/run/engine/docker.sock']['RW'] and not actual['/run/engine-tls']['RW']
   assert not any(m['Source'] in {'/var/run/docker.sock','/run/docker.sock'} or 'plugin' in m['Destination'] for m in config['Mounts'])
   check('packaged_broker_has_only_opaque_tls_relay_and_private_client_identity')

 def create_client(self,name):
  command=['create','--pull=never','--name',name,'--label','io.aegis.worker-proof='+self.nonce,'--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','64m','--pids-limit','64','--cpus','.25','--log-driver','none']
  for mount in self.client_mounts:command+=['--mount',mount]
  self.raw(command+[self.images['scanner-dispatch'],'run','/run/scan-broker/dispatch.sock','/run/dispatch-credential/client.credential'])
  config=json.loads(self.raw(['inspect',name]).stdout)[0];host=config['HostConfig'];assert config['Config']['Entrypoint']==['/aegis-scan-dispatch'] and config['Config']['User']=='10001:10001'
  assert host['NetworkMode']=='none' and host['ReadonlyRootfs'] and host['CapDrop']==['ALL'] and not host['Privileged'] and not host['GroupAdd']
  self.destinations=sorted(m['Destination'] for m in config['Mounts']);assert self.destinations==['/run/dispatch-credential','/run/scan-broker'] and all(not m['RW'] for m in config['Mounts'])
  assert not any(value.startswith(('DOCKER_HOST=','DOCKER_CONTEXT=','AEGIS_DATA=')) for value in config['Config'].get('Env',[]) or [])
  self.check('minimal_dispatch_client_has_no_engine_worker_credential_source_or_journal_mount')
 def assert_compose(self,resolved):
  services=resolved['services'];broker,client=services['scanner-broker'],services['scanner-dispatch'];profile='operator-broker-tls' if self.engine_fixture is not None else 'operator-broker';assert client['profiles']==[profile] and broker['profiles']==[profile]
  assert client['network_mode']=='none' and client['read_only'] and client['cap_drop']==['ALL'] and not client.get('group_add') and not client.get('environment')
  assert sorted(m['target'] for m in client['volumes'])==self.destinations and all(m.get('read_only') for m in client['volumes'])
  assert broker['command'][5]==self.binding['document']['worker_id']
  if self.engine_fixture is not None:
   assert not broker.get('group_add') and broker['environment']['AEGIS_SCANNER_ENGINE_TLS_DIR']=='/run/engine-tls'
   assert any(m['target']=='/run/engine-tls' and m.get('read_only') for m in broker['volumes'])
  else:assert broker['group_add']==[self.group]
  self.check('broker_compose_profile_separates_control_client_from_privileged_orchestrator')
 def proof(self,outcome):
  assert outcome['all_engine_writes_mediated'] is False and outcome['cleanup_release_authorized'] is False
  assert set(outcome)<= {'schema_version','state','job_id','request_digest','result_digest','receipt_count','all_engine_writes_mediated','cleanup_release_authorized'}
  return {'broker_binding':self.binding,'broker_images':self.images,'dispatch_outcome':outcome,'client_mount_destinations':self.destinations,'dispatch_client_has_engine_or_worker_authority':False,'controller_worker_selection_enforced':True}
 def cleanup_volumes(self):
  for volume in self.volumes:self.raw(['volume','rm',volume])
 def verify_removed(self):
  for volume in self.volumes:assert self.raw(['volume','inspect',volume],success=False).returncode!=0
