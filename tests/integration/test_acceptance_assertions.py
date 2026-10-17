#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Acceptance assertions must never disappear into a false PASS under -O."""
import ast
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
REFUSAL = 'Acceptance checks require Python assertions enabled'


class AcceptanceAssertionTests(unittest.TestCase):
    def test_optimization_refused_before_any_import_or_side_effect(self):
        checked = 0
        for directory in ('tests/integration', 'tests/negative-security'):
            for path in sorted((ROOT / directory).glob('*.py')):
                raw = path.read_text()
                if REFUSAL not in raw or not any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(raw))):
                    continue
                with self.subTest(script=path.name):
                    tree = ast.parse(raw)
                    first = tree.body[0]
                    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                        first = tree.body[1]
                    self.assertIsInstance(first, ast.If)
                    for flag in ('-O', '-OO'):
                        result = subprocess.run([sys.executable, flag, str(path)], capture_output=True, timeout=5)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, b'')
                        self.assertEqual(result.stderr.decode().strip(), REFUSAL)
                    checked += 1
        self.assertGreaterEqual(checked, 21)

    def test_every_assert_based_acceptance_module_has_optimization_guard(self):
        for directory in ('tests/integration', 'tests/negative-security'):
            for path in sorted((ROOT / directory).glob('*.py')):
                tree = ast.parse(path.read_text())
                if not any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
                    continue
                with self.subTest(script=path.name):
                    # Existing capability/operator guards also refuse optimized
                    # execution. Check the guard is at module scope, not dead
                    # text or an assertion (which -O itself removes).
                    guards = [node for node in tree.body if isinstance(node, ast.If)
                              and any(isinstance(n, ast.Name) and n.id == '__debug__' for n in ast.walk(node.test))
                              and any(isinstance(n, ast.Raise) for n in ast.walk(node))]
                    self.assertTrue(guards, 'Acceptance assertions can be optimized away')


if __name__ == '__main__':
    unittest.main()
