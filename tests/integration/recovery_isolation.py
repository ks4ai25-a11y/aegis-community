# SPDX-License-Identifier: BUSL-1.1
"""Pure namespace safety checks for the disposable recovery drill."""
import copy,re
SERVICES={'init','deployer','controller','gateway','verifier','demo-origin','fixture-origin'}
def prepare(spec):
 result=copy.deepcopy(spec);result.pop('name',None)
 for group in ('volumes','networks'):
  for entry in result.get(group,{}).values():
   if entry.get('external'):raise ValueError('external resources forbidden')
   entry.pop('name',None)
 for service in result['services'].values():service.pop('build',None);service['restart']='no'
 for name,port in [('gateway',8080),('controller',7410)]:result['services'][name]['ports']=[{'target':port,'host_ip':'127.0.0.1','published':'0','protocol':'tcp'}]
 return result

def validate(spec,project,fixture):
 if not re.fullmatch(r'aegis-(?:recovery|worker)-[0-9a-f]{24}',project):raise ValueError('unique drill project required')
 if set(spec.get('services',{}))!=SERVICES:raise ValueError('unexpected drill service')
 for group in ('volumes','networks'):
  for entry in spec.get(group,{}).values():
   if entry.get('external') or not entry.get('name','').startswith(project+'_'):raise ValueError('resource outside drill namespace')
 for name,service in spec['services'].items():
  if any(service.get(k) for k in ('container_name','volumes_from','external_links','privileged')):raise ValueError('shared or privileged service forbidden')
  if service.get('network_mode','') not in ('','none') or service.get('pid')=='host' or service.get('ipc')=='host':raise ValueError('shared host namespaces forbidden')
  for mount in service.get('volumes',[]):
   if mount['type']=='volume':
    if mount['source'] not in spec.get('volumes',{}):raise ValueError('unknown volume')
   elif not(mount['type']=='bind' and mount.get('read_only') and mount['target']=='/opt/aegis/repositories' and mount['source']==fixture):raise ValueError('unexpected host bind')
  for port in service.get('ports',[]):
   if name not in ('controller','gateway') or port.get('host_ip')!='127.0.0.1' or str(port.get('published'))!='0':raise ValueError('non-ephemeral or public port forbidden')
 return True
