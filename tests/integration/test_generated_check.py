#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""The freshness gate fails repeatedly without modifying a source checkout."""
import importlib.util
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('aegis_generated_check', ROOT / 'scripts/check_generated.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class GeneratedCheckTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='aegis-generated-source-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        (self.root / 'scripts').mkdir()
        for name in checker.GENERATORS:
            shutil.copyfile(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        for name in checker.generated_state(ROOT):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)

    def state(self):
        return {str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mtime_ns)
                for p in self.root.rglob('*') if p.is_file()}

    def test_clean_export_requires_no_git_and_is_unchanged(self):
        before = self.state()
        self.assertEqual(checker.stale_generated(self.root), [])
        self.assertEqual(self.state(), before)

    def test_tamper_fails_twice_without_repair(self):
        name = 'console/src/generated/contracts.ts'
        (self.root / name).write_text('// deliberately stale\n')
        before = self.state()
        for _ in range(2):
            self.assertIn(name, checker.stale_generated(self.root))
            self.assertEqual(self.state(), before)

    def test_missing_extra_and_package_marker_are_detected(self):
        missing = 'contracts/generated/research_client.go'
        extra = 'contracts/schemas/UnexpectedGeneratedV1.json'
        marker = 'contracts/generated/__init__.py'
        (self.root / missing).unlink()
        (self.root / extra).write_text('{}\n')
        (self.root / marker).write_text('# stale marker\n')
        before = self.state()
        changed = checker.stale_generated(self.root)
        for name in (missing, extra, marker):
            self.assertIn(name, changed)
        self.assertEqual(self.state(), before)

    def test_generator_failure_never_repairs_checkout(self):
        (self.root / 'scripts/generate_contracts.py').write_text('raise SystemExit(23)\n')
        before = self.state()
        with self.assertRaises(subprocess.CalledProcessError):
            checker.stale_generated(self.root)
        self.assertEqual(self.state(), before)

    def test_symlink_output_is_refused_without_following_it_for_generation(self):
        output = self.root / 'console/src/generated/contracts.ts'
        output.unlink()
        output.symlink_to(self.root / 'scripts/generate_contracts.py')
        before = (self.root / 'scripts/generate_contracts.py').read_bytes()
        with self.assertRaises(ValueError):
            checker.stale_generated(self.root)
        self.assertTrue(output.is_symlink())
        self.assertEqual((self.root / 'scripts/generate_contracts.py').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
