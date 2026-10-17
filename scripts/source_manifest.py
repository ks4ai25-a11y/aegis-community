#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Record source identity without generated caches, runtime state or credentials."""
import hashlib,json,pathlib
root=pathlib.Path(__file__).resolve().parents[1]
exclude={'node_modules','dist','bin','.git','__pycache__'}
files=[]
for p in sorted(root.rglob('*')):
 if not p.is_file() or any(s in exclude for s in p.relative_to(root).parts):continue
 rel=p.relative_to(root).as_posix()
 if rel.startswith('docs/evidence/') or p.name.endswith(('.tsbuildinfo','.db','.db-wal','.db-shm','.pem','.key')) or p.name.startswith('.env'):continue
 files.append({'path':rel,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
b=json.dumps(files,sort_keys=True,separators=(',',':')).encode()
out={'schema_version':'1.0','source_tree_sha256':'sha256:'+hashlib.sha256(b).hexdigest(),'files':files,'signature_status':'unsigned; source identity only, not publisher authenticity','git_commit':None}
(root/'docs/evidence/source-manifest.json').write_text(json.dumps(out,indent=2)+'\n')
print(out['source_tree_sha256'])
