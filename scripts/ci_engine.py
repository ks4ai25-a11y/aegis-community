#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Verify/extract a fixed engine for a disposable GitHub Linux CI job only."""
import hashlib,json,os,pathlib,platform,re,shutil,tarfile,tempfile,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
BINARIES={'containerd','runc','containerd-shim-runc-v2','docker','docker-proxy','ctr','dockerd','docker-init'}
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
def validate_lock(lock):
 if lock.get('schema_version')!='1.0' or lock.get('scope')!='disposable_github_linux_amd64_ci_only' or lock.get('publisher_signature_verified') is not False:raise ValueError('CI-only lock required')
 version=lock.get('version','')
 if not re.fullmatch(r'29\.[0-9]+\.[0-9]+',version) or lock.get('url')!='https://download.docker.com/linux/static/stable/x86_64/docker-'+version+'.tgz':raise ValueError('Fixed official archive required')
 if not re.fullmatch(r'sha256:[0-9a-f]{64}',lock.get('sha256','')) or not 0<lock.get('byte_count',0)<=150*1024*1024 or not 0<lock.get('maximum_unpacked_bytes',0)<=512*1024*1024:raise ValueError('Archive bounds required')
 members=lock.get('members',[]);expected={'docker',*('docker/'+name for name in BINARIES)}
 if len(members)!=len(expected) or {m.get('name') for m in members}!=expected or sum(m.get('bytes',0) for m in members)>lock['maximum_unpacked_bytes']:raise ValueError('Exact bounded member set required')
 for member in members:
  if member.get('kind')!=('directory' if member['name']=='docker' else 'file') or not isinstance(member.get('bytes'),int) or member['bytes']<0:raise ValueError('Regular archive entries required')
 return {m['name']:m for m in members}
def verify_archive(path,lock):
 digest=hashlib.sha256();size=0
 with pathlib.Path(path).open('rb') as source:
  while block:=source.read(65536):
   size+=len(block)
   if size>lock['byte_count']:raise ValueError('Archive exceeded pin')
   digest.update(block)
 if size!=lock['byte_count'] or 'sha256:'+digest.hexdigest()!=lock['sha256']:raise ValueError('Archive checksum differs from pin')
def prepare(lock,destination,archive):
 expected=validate_lock(lock);target=pathlib.Path(destination)
 if not target.is_absolute() or target.name in ('','..','.') or target.is_symlink() or target.exists():raise ValueError('New absolute destination required')
 parent=target.parent.resolve(strict=True);info=parent.stat()
 if info.st_uid!=os.geteuid() or info.st_mode&0o022:raise ValueError('Owned non-writable parent required')
 target=parent/target.name;verify_archive(archive,lock)
 # Validate the complete pinned member set before allocating the destination.
 with tarfile.open(archive,'r:gz') as source:
  seen=set();total=0
  for member in source:
   if member.name in seen or member.name not in expected or len(seen)>=9:raise ValueError('Unexpected archive entry')
   record=expected[member.name]
   if member.size!=record['bytes'] or (record['kind']=='file' and not member.isfile()) or (record['kind']=='directory' and not member.isdir()):raise ValueError('Unsafe archive entry')
   total+=member.size;seen.add(member.name)
   if total>lock['maximum_unpacked_bytes']:raise ValueError('Unpacked archive budget exceeded')
  if seen!=set(expected):raise ValueError('Incomplete archive')
 target.mkdir(mode=0o700);done=False
 try:
  (target/'bin').mkdir(mode=0o700)
  with tarfile.open(archive,'r:gz') as source:
   for member in source:
    if member.isdir():continue
    name=member.name.split('/')[1];path=target/'bin'/name
    stream=source.extractfile(member)
    if stream is None:raise ValueError('Missing binary bytes')
    with stream,path.open('xb') as output:
     remaining=member.size
     while remaining:
      block=stream.read(min(65536,remaining))
      if not block:raise ValueError('Incomplete binary')
      output.write(block);remaining-=len(block)
     if stream.read(1):raise ValueError('Extra binary bytes')
     output.flush();os.fsync(output.fileno())
    path.chmod(0o700)
  receipt={'schema_version':'1.0','scope':lock['scope'],'version':lock['version'],'archive_digest':lock['sha256'],'binary_count':len(BINARIES),'publisher_signature_verified':False}
  (target/'prepared.json').write_text(json.dumps(receipt,indent=2)+'\n');(target/'prepared.json').chmod(0o600);done=True;return receipt
 finally:
  if not done:shutil.rmtree(target)
def main():
 import sys
 if os.environ.get('GITHUB_ACTIONS')!='true' or platform.system()!='Linux' or platform.machine() not in ('x86_64','amd64'):raise SystemExit('Disposable GitHub Linux AMD64 CI only; no workstation daemon changes')
 if len(sys.argv)!=2:raise SystemExit('usage: ci_engine.py NEW_ABSOLUTE_DIRECTORY')
 lock=json.loads((ROOT/'tools/ci-engine.lock.json').read_text());validate_lock(lock)
 with tempfile.TemporaryDirectory(prefix='aegis-ci-engine-download-') as temporary:
  archive=pathlib.Path(temporary)/'engine.tgz';opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
  with opener.open(lock['url'],timeout=60) as response,archive.open('xb') as output:
   remaining=lock['byte_count']+1
   while block:=response.read(min(65536,remaining)):
    output.write(block);remaining-=len(block)
    if remaining==0:raise ValueError('Download exceeded pinned byte count')
  json.dump(prepare(lock,pathlib.Path(sys.argv[1]),archive),sys.stdout);print()
if __name__=='__main__':main()
