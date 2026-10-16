import copy,hashlib,io,json,pathlib,sys,tarfile,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]/'scripts'))
from ci_engine import prepare,validate_lock,BINARIES
from engine_authz_acceptance import public_create_failure
class CIEngine(unittest.TestCase):
 def test_public_native_failure_output_excludes_runtime_data(self):
  stage='native create failed: connection reused=true request written=true intent recorded=false response recorded=false'
  self.assertEqual(public_create_failure('    real_test.go:123: '+stage),stage)
  for line in ('real_test.go:123: '+stage+' secret-canary',
               'real_test.go:123: '+stage+'\x1b[31m',
               'real_test.go:123: '+stage.replace('true','/private/runtime',1),
               'real_test.go:123: Post https://127.0.0.1:12345/private-canary',
               '/private/source/real_test.go:123: '+stage,
               'authorization daemon allocation private-canary'):
   with self.subTest(line=line):self.assertIsNone(public_create_failure(line))
 def fixture(self,parent,fault=''):
  archive=parent/'archive.tgz';members=[]
  with tarfile.open(archive,'w:gz') as output:
   entry=tarfile.TarInfo('docker');entry.type=tarfile.DIRTYPE;output.addfile(entry);members.append({'name':'docker','kind':'directory','bytes':0})
   for name in sorted(BINARIES):
    value=b'\x7fELFsynthetic-'+name.encode();entry=tarfile.TarInfo('docker/'+name);entry.size=len(value)
    if fault=='link' and name=='docker':entry.type=tarfile.SYMTYPE;entry.linkname='/sensitive';entry.size=0
    if fault=='traversal' and name=='docker':entry.name='docker/../escape'
    output.addfile(entry,io.BytesIO(value));members.append({'name':'docker/'+name,'kind':'file','bytes':len(value)})
   if fault=='duplicate':output.addfile(tarfile.TarInfo('docker'))
  lock={'schema_version':'1.0','scope':'disposable_github_linux_amd64_ci_only','version':'29.8.2','url':'https://download.docker.com/linux/static/stable/x86_64/docker-29.8.2.tgz','sha256':'sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest(),'byte_count':archive.stat().st_size,'maximum_unpacked_bytes':512*1024*1024,'members':members,'publisher_signature_verified':False}
  return lock,archive
 def test_fixed_members_verified_before_private_extraction(self):
  with tempfile.TemporaryDirectory() as temporary:
   parent=pathlib.Path(temporary).resolve();lock,archive=self.fixture(parent);target=parent/'ready';receipt=prepare(lock,target,archive)
   self.assertEqual(receipt['binary_count'],8);self.assertFalse(receipt['publisher_signature_verified']);self.assertEqual(target.stat().st_mode&0o777,0o700)
   self.assertEqual({p.name for p in (target/'bin').iterdir()},BINARIES)
   for p in (target/'bin').iterdir():self.assertEqual(p.stat().st_mode&0o777,0o700)
   with self.assertRaises(ValueError):prepare(lock,target,archive)
 def test_checksum_and_archive_hazards_allocate_no_output(self):
  for fault in ('hash','size','link','traversal','duplicate'):
   with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
    parent=pathlib.Path(temporary).resolve();lock,archive=self.fixture(parent,fault)
    if fault=='hash':lock['sha256']='sha256:'+'0'*64
    if fault=='size':lock['byte_count']+=1
    with self.assertRaises(ValueError):prepare(lock,parent/'refused',archive)
    self.assertFalse((parent/'refused').exists())
 def test_unpinned_host_or_members_refused(self):
  with tempfile.TemporaryDirectory() as temporary:
   lock,_=self.fixture(pathlib.Path(temporary))
   for field,value in [('url','https://untrusted.invalid/engine.tgz'),('scope','operator_install'),('publisher_signature_verified',True),('members',[])]:
    invalid=copy.deepcopy(lock);invalid[field]=value
    with self.assertRaises(ValueError):validate_lock(invalid)
