#!/usr/bin/env python3
"""Pinned Bandit integration over trusted inert, test-owned source only."""
import json,pathlib,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,'/private/tmp/aegis-contract-qa')
import jsonschema
validator=jsonschema.Draft202012Validator(json.loads((ROOT/'contracts/schemas/ScannerExecutionV1.json').read_text()))
checks=[]
report={'schema_version':'1.0','scope':'pinned-offline-Bandit-trusted-fixture-controls','checks':checks,'started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
def scan(src):
 result=subprocess.run([str(ROOT/'bin/aegis-research'),'scan-offline','bandit',str(src.resolve()),str(ROOT)],capture_output=True,timeout=145)
 assert result.stdout,'Scanner preflight returned no execution receipt'
 receipt=json.loads(result.stdout);validator.validate(receipt)
 assert receipt['parser_version']=='1.1'
 assert receipt['tool_version']=='1.9.4' and receipt['cleanup_state']=='complete'
 assert receipt['invocation']['network_profile']=='none'
 assert receipt['invocation']['args']==['--ini','/dev/null','--ignore-nosec','-r','/src','-f','json']
 return result,receipt
try:
 with tempfile.TemporaryDirectory(prefix='aegis-bandit-controls-') as temp:
  src=pathlib.Path(temp).resolve()
  (src/'.bandit').write_text('[bandit]\nskips = B608\n')
  (src/'query.py').write_text('raise RuntimeError("AEGIS_SOURCE_EXECUTED_CANARY")\ndef query(db, name):\n    return db.execute("SELECT * FROM products WHERE name=\\\'" + name + "\\\'") # nosec B608\n')
  result,receipt=scan(src)
  assert result.returncode==0 and receipt['status']=='completed' and receipt['exit_code']==1
  assert {f['path'] for f in receipt['source_snapshot']['files']}=={'.bandit','query.py'}
  assert any(p['rule_id']=='B608' for f in receipt['result']['findings'] for p in f['provenance'])
  assert all(f['evidence_tier']=='T0' and f['status']=='suspected' for f in receipt['result']['findings'])
  assert 'AEGIS_SOURCE_EXECUTED_CANARY' not in json.dumps(receipt)
  checks.append({'id':'repository_ini_and_nosec_do_not_suppress_B608','result':'PASS','execution':receipt})
  print(checks[-1]['id']+': PASS',flush=True)
  checks.append({'id':'top_level_source_canary_not_executed_or_exported','result':'PASS'})
  (src/'query.py').write_text('def broken(: # AEGIS_PRIVATE_PARSE_CANARY\n')
  result,receipt=scan(src)
  assert result.returncode==0 and receipt['status']=='completed_partial' and not receipt['result']['findings']
  assert any(d['code']=='SCAN_PARTIAL' for d in receipt['result']['diagnostics'])
  assert 'AEGIS_PRIVATE_PARSE_CANARY' not in json.dumps(receipt)
  checks.append({'id':'syntax_error_is_partial_not_clean_completion','result':'PASS','execution':receipt})
  print(checks[-1]['id']+': PASS',flush=True)
 report['overall']='PASS'
except Exception as error:
 report['overall']='FAIL';report['error']=str(error)[:1800];raise
finally:
 report['completed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
 report['limitations']=['Only trusted inert fixtures and local ARM64 Docker Desktop tested.','Publisher signature, full transitive notices and independent isolation review remain pending.','Static Bandit claims are not exploit, fix or global safety evidence.']
 (ROOT/'docs/evidence/bandit-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
