#!/usr/bin/env python3
"""Exercise the compiled local snapshot CLI using only private synthetic state."""
import datetime, hashlib, json, os, pathlib, re, sqlite3, stat, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
if not __debug__:
    raise SystemExit('Snapshot proof requires Python assertions enabled')
checks = []
payloads = []

def check(name):
    checks.append({'id': name, 'result': 'PASS'})
    print(name + ': PASS', flush=True)

with tempfile.TemporaryDirectory(prefix='aegis-snapshot-proof-') as temporary:
    parent = pathlib.Path(temporary).resolve()
    binary = parent / 'aegisctl'
    subprocess.run(['go', 'build', '-trimpath', '-o', str(binary), './cmd/aegisctl'], cwd=ROOT / 'controller', check=True, capture_output=True, timeout=180)
    data = parent / 'state'
    data.mkdir(mode=0o700)
    env = {**os.environ, 'AEGIS_DATA': str(data), 'GATEWAY_POLICY_ROOT': str(data)}
    def run(*args, success=True):
        result = subprocess.run([str(binary), *args], env=env, capture_output=True, text=True, timeout=40)
        assert result.returncode == (0 if success else 1), 'unexpected CLI exit code'
        return result
    help_result = run('backup', '--help')
    assert 'backup create ABSOLUTE_FILE [--json]' in help_result.stdout
    assert not (data / 'aegis.db').exists()
    check('help_does_not_create_database')
    missing = parent / 'missing-state'
    wrong_env = {**env, 'AEGIS_DATA': str(missing)}
    refused = subprocess.run([str(binary), 'backup', 'create', str(parent / 'must-not-exist.db'), '--json'], env=wrong_env, capture_output=True, text=True, timeout=40)
    assert refused.returncode == 1 and not refused.stdout
    assert not missing.exists() and not (parent / 'must-not-exist.db').exists()
    check('missing_source_never_initializes_or_reports_empty_backup')
    run('init')
    marker = 'deleted-private-snapshot-canary-XXXXXXXXXXXXXXXXXXXXXXXX'
    private_value = 'synthetic-local-only-owner-value'
    source = data / 'aegis.db'
    with sqlite3.connect(source) as database:
        database.execute('PRAGMA secure_delete=OFF')
        database.execute("INSERT INTO settings VALUES('snapshot-private-canary', ?)", (private_value,))
        database.execute('CREATE TABLE retired_snapshot_canary(value TEXT)')
        database.execute('INSERT INTO retired_snapshot_canary VALUES(?)', (marker * 1024,))
        database.commit()
        database.execute('DELETE FROM retired_snapshot_canary')
        database.commit()
        database.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    assert marker.encode() in source.read_bytes()
    output = parent / 'snapshot.db'
    result = run('backup', 'create', str(output), '--json')
    receipt = json.loads(result.stdout)
    schema = json.loads((ROOT / 'contracts/schemas/DatabaseSnapshotReceiptV1.json').read_text())
    assert set(receipt) == set(schema['properties']) == set(schema['required'])
    assert receipt['schema_version'] == '1.0' and receipt['status'] == 'created'
    assert receipt['scope'] == 'controller_database_only'
    assert type(receipt['byte_count']) is int and 100 <= receipt['byte_count'] <= 536870912
    assert re.fullmatch(r'sha256:[0-9a-f]{64}', receipt['database_digest'])
    assert datetime.datetime.fromisoformat(receipt['created_at'].replace('Z', '+00:00')).utcoffset() == datetime.timedelta(0)
    for key in ('gateway_configuration_captured', 'tool_manifest_captured', 'restore_verified'):
        assert receipt[key] is False
    assert private_value not in result.stdout and str(parent) not in result.stdout and marker not in result.stdout
    payloads.append(receipt)
    check('json_receipt_has_exact_declared_fields_bounds_and_false_recovery_flags')
    artifact = output.read_bytes()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert receipt['byte_count'] == len(artifact)
    assert receipt['database_digest'] == 'sha256:' + hashlib.sha256(artifact).hexdigest()
    assert marker.encode() not in artifact
    with sqlite3.connect(output.as_uri() + '?mode=ro&immutable=1', uri=True) as snapshot:
        assert snapshot.execute('PRAGMA quick_check').fetchone() == ('ok',)
        assert snapshot.execute("SELECT value FROM settings WHERE key='snapshot-private-canary'").fetchone() == (private_value,)
        assert snapshot.execute('SELECT count(*) FROM retired_snapshot_canary').fetchone() == (0,)
    check('private_snapshot_preserves_committed_state_without_deleted_canary')
    repeated = run('backup', 'create', str(output), '--json', success=False)
    assert not repeated.stdout and output.read_bytes() == artifact
    check('repeat_never_overwrites_existing_snapshot_or_claims_success')
    legacy = parent / 'legacy.db'
    legacy_receipt = json.loads(run('backup', str(legacy), '--json').stdout)
    assert legacy_receipt['scope'] == 'controller_database_only' and legacy_receipt['restore_verified'] is False
    check('legacy_explicit_destination_uses_same_private_backend')
    sentinel = parent / 'sentinel'
    sentinel.write_bytes(b'owned fixture sentinel')
    linked = parent / 'linked.db'
    linked.symlink_to(sentinel)
    refused = run('backup', 'create', str(linked), '--json', success=False)
    assert not refused.stdout and sentinel.read_bytes() == b'owned fixture sentinel'
    check('symlink_target_unchanged')
    fifo = parent / 'fifo.db'
    os.mkfifo(fifo, 0o600)
    assert not run('backup', 'create', str(fifo), '--json', success=False).stdout
    check('fifo_refused_without_waiting_for_reader')
    for args in (('create',), ('relative.db', '--json'), ('create', str(parent / 'other.db'), '--unknown')):
        assert not run('backup', *args, success=False).stdout
    check('ambiguous_relative_and_unknown_arguments_refused')
    writable = parent / 'writable'
    writable.mkdir(mode=0o700)
    writable.chmod(0o777)
    assert not run('backup', 'create', str(writable / 'refused.db'), '--json', success=False).stdout
    assert not (writable / 'refused.db').exists()
    writable.chmod(0o700)
    check('group_or_other_writable_destination_parent_refused')
    assert not list(parent.glob('.aegis-backup-*')) and not list(data.glob('.aegis-backup-*'))
    with sqlite3.connect(source.as_uri() + '?mode=ro&immutable=1', uri=True) as live:
        assert live.execute("SELECT value FROM settings WHERE key='snapshot-private-canary'").fetchone() == (private_value,)
    check('handled_failures_leave_no_staging_and_preserve_source')
    report = {'schema_version': '1.0', 'status': 'PASS', 'scope': 'synthetic native CLI controller-database snapshots; application restore is unverified', 'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checks': checks, 'receipt': payloads[0], 'binary_digest': 'sha256:' + hashlib.sha256(binary.read_bytes()).hexdigest()}
    evidence = os.environ.get('AEGIS_SNAPSHOT_EVIDENCE')
    if evidence:
        pathlib.Path(evidence).write_text(json.dumps(report, indent=2) + '\n')
    print('native_snapshot_checks: ' + str(len(checks)), flush=True)
