# Private controller database snapshots

Aegis provides a local controller-database snapshot command on Linux/macOS. This is one recovery component. Gateway configuration and tool manifests are not captured, and application restore is not verified. GATE-11 remains incomplete.

```text
aegisctl backup --help
aegisctl backup create /absolute/owned/export/snapshot.db --json
```

Run with the same operator identity that owns the controller data. `AEGIS_DATA` selects the existing controller data directory; its default is `/var/lib/aegis`. The destination parent must already exist, belong to this operator and prohibit group/other writes. The destination must be a new absolute path. The legacy `backup ABSOLUTE_FILE` form uses the same private backend. Errors return a nonzero exit status and no successful JSON receipt.

The source must already be recognized Aegis state. Missing or empty sources are refused. The command opens it read-only/query-only and validates known migration checksums without initializing or upgrading it; recognized older migration prefixes can be captured before an upgrade. It copies a pinned SQLite read snapshot through the online backup API. It does not copy the live database/WAL as ordinary files. Concurrent controller WAL writes can continue. The private destination is compacted and checked before publication, so retired freelist data is not carried into the published snapshot. Staging uses mode 0700; database bytes use mode 0600 from creation. A late existing destination, symlink or FIFO is refused. Successful output is synced before the command reports completion.

Bounds are thirty seconds, 512 MiB and a finite page-step budget. Compaction needs additional temporary disk space. Group/other-writable directories and filesystems without the required Unix ownership/hard-link semantics are unsupported. Disk or context failure does not produce a success receipt. A failure after final publication can leave a complete private file with uncertain durability; inspect it separately and select a new destination for another attempt. A process crash can leave a private `.aegis-backup-*` staging directory; automatic crash cleanup is not implemented.

The JSON receipt includes an artifact checksum and byte count. Its scope is `controller_database_only`, with these required fields:

```json
{
  "gateway_configuration_captured": false,
  "tool_manifest_captured": false,
  "restore_verified": false
}
```

The receipt contains no database contents, credentials or host paths. A checksum establishes byte identity; it is not a signature, an authorization receipt or independent security review. The snapshot itself remains sensitive owner state, including account hashes, authority records and private review history. It is not application-encrypted and must remain protected locally. No upload or provider export is performed.

Application restore is unavailable through this database-only command. The separate [recovery bundle workflow](recovery-bundles.md) binds matching demo gateway/policy/tool revisions and provides a confirmed offline restore with session and capability revocation. Its isolated synthetic application drill is scoped to the current demo profile. Existing database-only backup files are not automatically converted, activated or installed.

See [ADR 043](../architecture/adr/043-private-controller-database-snapshots.md) and [observed evidence](../evidence/database-snapshot-acceptance.json). Native synthetic CLI and store failure checks are integrated into `make test`. The explicit packaged check uses `AEGIS_LIVE_SNAPSHOT_TEST=1 python3 tests/integration/database_snapshot_packaged_acceptance.py`; it retains private snapshots inside the owned local Aegis data volume, pins a local Unix engine and never exports database bytes. Its isolated offline audit-copy check is not an application restore.
