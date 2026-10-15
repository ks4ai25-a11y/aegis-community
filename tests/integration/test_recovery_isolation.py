import unittest
from recovery_isolation import prepare,validate,SERVICES
class Isolation(unittest.TestCase):
 def baseline(self):
  project='aegis-recovery-'+'a'*24
  source={'name':'aegis-community','services':{x:{'volumes':[]} for x in SERVICES},'volumes':{'data':{'name':'aegis-community_controller_data'}},'networks':{'net':{'name':'aegis-community_origin_net'}}}
  ready=prepare(source)
  self.assertEqual(source['volumes']['data']['name'],'aegis-community_controller_data')
  self.assertNotIn('name',ready['volumes']['data'])
  ready['volumes']['data']['name']=project+'_data';ready['networks']['net']['name']=project+'_net'
  return project,ready
 def test_resolved_shared_names_removed_and_original_unchanged(self):
  project,spec=self.baseline();self.assertTrue(validate(spec,project,'/fixture'))
 def test_worker_namespace_uses_the_same_resource_isolation(self):
  project,spec=self.baseline();worker='aegis-worker-'+'b'*24
  for group in ('volumes','networks'):
   for value in spec[group].values():value['name']=value['name'].replace(project,worker)
  self.assertTrue(validate(spec,worker,'/fixture'))
 def test_shared_resources_refused_before_creation(self):
  for group in ('volumes','networks'):
   project,spec=self.baseline();next(iter(spec[group].values()))['name']='aegis-community_shared'
   with self.assertRaises(ValueError):validate(spec,project,'/fixture')
 def test_external_bind_privilege_and_ports_refused(self):
  for kind in ('external','bind','privileged','container_name','port','host_network'):
   project,spec=self.baseline()
   if kind=='external':spec['volumes']['data']['external']=True
   if kind=='bind':spec['services']['controller']['volumes']=[{'type':'bind','source':'/sensitive','target':'/data','read_only':True}]
   if kind=='privileged':spec['services']['controller']['privileged']=True
   if kind=='container_name':spec['services']['controller']['container_name']='existing-controller'
   if kind=='port':spec['services']['controller']['ports'][0]['published']='7410'
   if kind=='host_network':spec['services']['controller']['network_mode']='host'
   with self.assertRaises(ValueError):validate(spec,project,'/fixture')
