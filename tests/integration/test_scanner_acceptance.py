#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Check that scanner acceptance distinguishes failure, absence and skipped scope."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import scanner_acceptance

from scanner_acceptance import DATABASE_REASON, validate_checks


class ScannerAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.checks = {}
        rules = {
            'semgrep_ce': 'rules.aegis.synthetic-python-sql-concat',
            'gitleaks': 'github-pat',
            'bandit': 'B608',
        }
        for tool, rule in rules.items():
            self.add(tool + '-vulnerable', findings=[{'provenance': [{'rule_id': rule}]}])
            self.add(tool + '-safe', findings=[])
        for fixture, version in [('vulnerable', '4.17.20'), ('safe', '4.17.21')]:
            self.add('syft-' + fixture, findings=[], sbom={
                'bomFormat': 'CycloneDX',
                'components': [{'name': 'lodash', 'version': version}],
            })
        for tool in ('osv_v2', 'trivy'):
            for fixture in ('vulnerable', 'safe'):
                self.add(tool + '-' + fixture, status='not_run', reason=DATABASE_REASON)

    def add(self, name, status='completed', **fields):
        self.checks[name] = {'id': name, 'status': status, **fields}

    def test_expected_controls_and_explicit_skips_pass(self):
        self.assertEqual(validate_checks(list(self.checks.values())), [])

    def test_outcomes_previously_mistaken_for_success_fail(self):
        regressions = (
            ('bandit-safe', {'status': 'tool_error'}),
            ('bandit-safe', {'status': 'completed_partial'}),
            ('bandit-safe', {'findings': [{'provenance': [{'rule_id': 'B608'}]}]}),
            ('gitleaks-vulnerable', {'findings': [{'provenance': [{'rule_id': 'unrelated'}]}]}),
            ('semgrep_ce-vulnerable', {'status': 'completed_partial'}),
            ('syft-safe', {'status': 'tool_error'}),
            ('syft-vulnerable', {'sbom': {'bomFormat': 'CycloneDX', 'components': []}}),
            ('osv_v2-safe', {'status': 'completed', 'findings': []}),
            ('trivy-vulnerable', {'status': 'tool_error'}),
        )
        for name, changes in regressions:
            with self.subTest(name=name, changes=changes):
                altered = copy.deepcopy(self.checks)
                altered[name].update(changes)
                self.assertTrue(validate_checks(list(altered.values())))

    def test_missing_or_duplicate_controls_fail(self):
        checks = list(self.checks.values())
        self.assertTrue(validate_checks(checks[:-1]))
        self.assertTrue(validate_checks(checks[:-1] + checks[:1]))

    def test_failed_run_preserves_evidence_and_never_invokes_database_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'tools').mkdir()
            (root / 'docs/evidence').mkdir(parents=True)
            tools = ['semgrep_ce', 'bandit', 'gitleaks', 'syft', 'osv_v2', 'trivy']
            (root / 'tools/scanners.lock.json').write_text(
                json.dumps({'tools': [{'id': tool} for tool in tools]}))
            evidence = root / 'docs/evidence/scanner-acceptance.json'
            evidence.write_bytes(b'previous verified evidence\n')

            def outcome(tool, fixture, invocation):
                name = tool['id'] + '-' + fixture
                return self.checks[name]

            self.checks['bandit-safe']['status'] = 'tool_error'
            with (patch.object(scanner_acceptance, 'ROOT', root),
                  patch.object(scanner_acceptance, 'scan_fixture', side_effect=outcome),
                  patch.object(scanner_acceptance.subprocess, 'check_output', return_value=b'{}') as invoke,
                  redirect_stdout(io.StringIO())):
                with self.assertRaisesRegex(SystemExit, 'bandit: safe control'):
                    scanner_acceptance.main()
                self.assertEqual(evidence.read_bytes(), b'previous verified evidence\n')
                self.assertEqual([call.args[0][-1] for call in invoke.call_args_list], tools[:4])
                self.checks['bandit-safe']['status'] = 'completed'
                scanner_acceptance.main()
                report = json.loads(evidence.read_text())
                self.assertEqual(report['result'], 'PASS')
                skipped = [check for check in report['checks'] if check['status'] == 'not_run']
                self.assertEqual(len(skipped), 4)
