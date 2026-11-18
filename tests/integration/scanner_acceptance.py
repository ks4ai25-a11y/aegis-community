#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Operator-launched pinned tools; only the trusted bundled inert fixture is mounted."""
if not __debug__:
 raise SystemExit('Acceptance checks require Python assertions enabled')
import hashlib,json,pathlib,resource,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
BINARY=ROOT/'bin/aegis-research'
STATIC_RULES = {
 'semgrep_ce': 'rules.aegis.synthetic-python-sql-concat',
 'gitleaks': 'github-pat',
 'bandit': 'B608',
}
DATABASE_TOOLS = {'osv_v2', 'trivy'}
DATABASE_REASON = 'offline_database_not_provisioned_by_this_harness'


def validate_checks(checks):
 expected = {tool+'-'+fixture for tool in (*STATIC_RULES, 'syft', *DATABASE_TOOLS)
             for fixture in ('vulnerable', 'safe')}
 by_id = {check['id']: check for check in checks}
 if len(checks) != len(expected) or by_id.keys() != expected:
  return ['fixture coverage is missing, duplicated or unexpected']
 failures = []
 for tool, rule in STATIC_RULES.items():
  positive, negative = by_id[tool+'-vulnerable'], by_id[tool+'-safe']
  if positive.get('status') != 'completed' or not any(
      item.get('rule_id') == rule
      for finding in positive.get('findings', [])
      for item in finding.get('provenance', [])):
   failures.append(tool+': expected positive control did not complete with its fixture rule')
  if negative.get('status') != 'completed' or negative.get('findings') != []:
   failures.append(tool+': safe control did not complete with zero findings')
 for fixture, version in [('vulnerable', '4.17.20'), ('safe', '4.17.21')]:
  check = by_id['syft-'+fixture]
  sbom = check.get('sbom') or {}
  versions = {component.get('version') for component in sbom.get('components', [])
              if component.get('name') == 'lodash'}
  if (check.get('status') != 'completed' or check.get('findings') != []
      or sbom.get('bomFormat') != 'CycloneDX' or versions != {version}):
   failures.append('syft-'+fixture+': expected fixture dependency inventory was not produced')
 for tool in sorted(DATABASE_TOOLS):
  for fixture in ('vulnerable', 'safe'):
   check = by_id[tool+'-'+fixture]
   if (check.get('status') != 'not_run' or check.get('reason') != DATABASE_REASON
       or 'findings' in check or 'sbom' in check):
    failures.append(check['id']+': expected an explicit offline-database skip')
 return failures


OUTPUT_LIMIT = 8 << 20


def limit_output():
 resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT, OUTPUT_LIMIT))


def scan_fixture(tool, fixture, invocation):
 src = (ROOT/'alpha/fixtures/scanners'/fixture).resolve()
 data = b''.join(p.name.encode()+b'\0'+p.read_bytes() for p in sorted(src.iterdir()))
 input_digest = 'sha256:'+hashlib.sha256(data).hexdigest()
 image_digest = tool['image'].split('@')[1]
 result = {'id': tool['id']+'-'+fixture, 'tool_version': tool['version'],
           'image_digest': image_digest, 'input_digest': input_digest}
 args = ['docker', 'run', '--rm', '--pull=never', '--network=none',
         '--read-only', '--user=10001:10001', '--cap-drop=ALL',
         '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=768m',
         '--cpus=1', '--log-driver=none', '--tmpfs',
         '/tmp:rw,nosuid,size=96m,uid=10001,gid=10001',
         '-e', 'HOME=/tmp', '-e', 'SEMGREP_SEND_METRICS=off',
         '-v', str(src)+':/src:ro', '-v', str(ROOT/'alpha/rules')+':/rules:ro',
         tool['image'], *invocation['args']]
 started = time.monotonic()
 with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
  try:
   run = subprocess.run(args, stdout=out, stderr=err, timeout=125,
                        preexec_fn=limit_output)
   result['exit_code'] = run.returncode
   out.seek(0)
   raw = out.read(OUTPUT_LIMIT+1)
   if run.returncode not in invocation['finding_exit_codes'] or len(raw) >= OUTPUT_LIMIT:
    return dict(result, status='tool_error', reason='scanner_failed_or_output_limit')
   parsed = subprocess.run(
       [str(BINARY), 'parse', tool['id'], tool['version'], image_digest, input_digest],
       input=raw, capture_output=True, timeout=20)
   if parsed.returncode:
    return dict(result, status='tool_error', reason='parser_failed')
   normalized = json.loads(parsed.stdout)
   result.update(status=normalized['status'], findings=normalized['findings'],
                 diagnostics=normalized['diagnostics'])
   if 'sbom' in normalized:
    result['sbom'] = normalized['sbom']
   if 'ghp_' in json.dumps(result):
    return {'id': result['id'], 'status': 'tool_error', 'reason': 'credential_canary_retained'}
  except subprocess.TimeoutExpired:
   return dict(result, status='tool_error', reason='timeout')
  except (OSError, ValueError, TypeError, KeyError):
   return dict(result, status='tool_error', reason='fixture_execution_unavailable')
 result['elapsed_seconds'] = round(time.monotonic()-started, 3)
 return result


def main():
 tools = json.loads((ROOT/'tools/scanners.lock.json').read_text())['tools']
 report = {'schema_version': '1.0', 'scope': 'trusted-bundled-static-fixtures',
           'checks': [], 'limitations': [
            'Publisher signatures and licence review pending.',
            'OSV and Trivy are covered by separate offline database acceptance.',
            'No repository code or package scripts executed.',
           ]}
 for tool in tools:
  fixtures = ('vulnerable', 'safe')
  if tool['id'] in DATABASE_TOOLS:
   for fixture in fixtures:
    name = tool['id']+'-'+fixture
    report['checks'].append({'id': name, 'status': 'not_run', 'reason': DATABASE_REASON})
    print(name+': NOT RUN (offline database required)', flush=True)
   continue
  invocation = json.loads(subprocess.check_output(
      [str(BINARY), 'invocation', tool['id']], timeout=10))
  for fixture in fixtures:
   result = scan_fixture(tool, fixture, invocation)
   report['checks'].append(result)
   print(result['id']+': '+result['status']+' findings='+str(len(result.get('findings', []))),
         flush=True)
 report['completed_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
 failures = validate_checks(report['checks'])
 if failures:
  raise SystemExit('Scanner acceptance FAILED: '+'; '.join(failures))
 report['result'] = 'PASS'
 report['failures'] = []
 (ROOT/'docs/evidence/scanner-acceptance.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
 main()
