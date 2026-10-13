#!/usr/bin/env python3
"""Real fixed scanners over private snapshots, with guard and cleanup receipts."""
import hashlib,json,os,pathlib,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,'/private/tmp/aegis-contract-qa')
import jsonschema
schema=json.loads((ROOT/'contracts/schemas/ScannerExecutionV1.json').read_text())
validator=jsonschema.Draft202012Validator(schema)
checks=[]
report={'schema_version':'1.0','scope':'operator-launched-pinned-offline-snapshot-fixtures','checks':checks,'started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
try:
 for tool in ['semgrep_ce','gitleaks','syft','osv_v2','trivy']:
  for fixture in ['vulnerable','safe']:
   src=ROOT/'alpha/fixtures/scanners'/fixture
   command=[str(ROOT/'bin/aegis-research'),'scan-offline',tool,str(src),str(ROOT)]
   run=subprocess.run(command,capture_output=True,timeout=150)
   receipt=json.loads(run.stdout);validator.validate(receipt)
   assert receipt['cleanup_state']=='complete',receipt['cleanup_state']
   assert 'ghp_' not in json.dumps(receipt)
   expected={p.name:'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest() for p in src.iterdir() if p.is_file()}
   assert {f['path']:f['digest'] for f in receipt['source_snapshot']['files']}==expected
   assert all(s['input_digest']==receipt['source_snapshot']['snapshot_digest'] for f in receipt['result']['findings'] for s in f['provenance'])
   if tool in ['semgrep_ce','gitleaks']:
    assert run.returncode==0 and receipt['status']=='completed'
    assert len(receipt['result']['findings'])==(1 if fixture=='vulnerable' else 0)
   elif tool=='syft':
    assert run.returncode==0 and receipt['status']=='completed'
    packages=receipt['result']['sbom']['components']
    assert any(p['name']=='lodash' and p['version']==('4.17.20' if fixture=='vulnerable' else '4.17.21') for p in packages)
   else:
    assert run.returncode==1 and receipt['status']=='tool_error' and not receipt['result']['findings']
   checks.append({'id':tool+'-'+fixture,'result':'PASS','execution':receipt})
   print(tool+'-'+fixture+': '+receipt['status']+' cleanup='+receipt['cleanup_state'],flush=True)
 report['overall']='PASS'
except Exception as e:
 report['overall']='FAIL';report['error']=str(e)[:1800];raise
finally:
 report['completed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
 report['limitations']=['Only trusted bundled inert inputs and local Docker Desktop tested.','OSV/Trivy missing offline databases remain tool_error; no coverage or exploitability claim.','Operator-launched executor is not durable controller job orchestration.','Publisher signature/licence review, larger rule packs, automatic durable job recovery and independent review remain pending.']
 (ROOT/'docs/evidence/snapshot-scanner-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
