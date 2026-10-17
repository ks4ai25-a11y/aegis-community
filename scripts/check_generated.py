#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Compare an isolated regeneration with source files; never repair the checkout."""
import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile

GENERATORS = ('generate_contracts.py', 'generate_research_api.py')
DIRECTORIES = ('contracts/schemas', 'contracts/generated', 'console/src/generated')


def generated_state(root):
    paths = list((root / 'contracts/schemas').glob('*.json'))
    paths += list((root / 'contracts/generated').glob('contracts.*'))
    paths += list((root / 'contracts/generated').glob('research_client.*'))
    paths += [root / name for name in (
        'contracts/generated/__init__.py', 'contracts/openapi-research.json',
        'console/src/generated/contracts.ts', 'console/src/generated/research-client.ts')]
    state = {}
    for path in paths:
        if path.suffix == '.pyc':
            continue
        if path.is_symlink():
            raise ValueError('Generated output must be a regular file: ' + str(path.relative_to(root)))
        if path.is_file():
            state[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return state


def stale_generated(root):
    root = pathlib.Path(root).resolve(strict=True)
    before = generated_state(root)
    # A fresh skeleton prevents stale schemas/extra outputs from becoming
    # accidental generator inputs. No Git metadata, runtime files or modules
    # are needed. mkdtemp's private directory works on Linux and macOS.
    with tempfile.TemporaryDirectory(prefix='aegis-generated-check-') as temporary:
        isolated = pathlib.Path(temporary)
        (isolated / 'scripts').mkdir()
        for directory in DIRECTORIES:
            (isolated / directory).mkdir(parents=True)
        for name in GENERATORS:
            shutil.copyfile(root / 'scripts' / name, isolated / 'scripts' / name)
        for name in GENERATORS:
            subprocess.run([sys.executable, str(isolated / 'scripts' / name)], cwd=isolated, check=True)
        expected = generated_state(isolated)
    return sorted(name for name in before.keys() | expected.keys() if before.get(name) != expected.get(name))


def main():
    changed = stale_generated(pathlib.Path(__file__).resolve().parents[1])
    if changed:
        raise SystemExit('Generated files are stale: ' + ', '.join(changed))
    print('Generated schemas, bindings and clients are reproducible')


if __name__ == '__main__':
    main()
