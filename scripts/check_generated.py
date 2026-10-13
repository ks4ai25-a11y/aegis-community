#!/usr/bin/env python3
"""Verify generated files are reproducible without requiring a Git checkout."""
import hashlib,pathlib,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1]
paths=list((root/'contracts/schemas').glob('*.json'))+list((root/'contracts/generated').glob('contracts.*'))+list((root/'contracts/generated').glob('research_client.*'))+[root/'contracts/openapi-research.json',root/'console/src/generated/contracts.ts',root/'console/src/generated/research-client.ts']
paths=[p for p in paths if p.suffix!='.pyc']
before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
for script in ['generate_contracts.py','generate_research_api.py']:subprocess.run([sys.executable,str(root/'scripts'/script)],cwd=root,check=True)
changed=[p for p,d in before.items() if hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()!=d]
if changed:raise SystemExit('Generated files were stale: '+', '.join(changed))
print('Generated schemas, bindings and clients are reproducible')
