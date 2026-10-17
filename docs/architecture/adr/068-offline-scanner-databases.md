# ADR 068: Offline vulnerability databases for OSV-Scanner and Trivy

Status: provisioning, verification and executor integration implemented and validated with real data; controller digest approval and the admitted SDK mount allowlist pending.

## Problem

OSV-Scanner and Trivy run with `--network none` and an empty tmpfs home, so they always ended as tool errors and known-vulnerable dependencies were never reported (GATE-6, D3).

## Decision

`alpha/scannerdb` (no executor or engine imports) and the separate `alpha/cmd/aegis-scanner-db` binary provide:

- `fetch`: the only networked step. OSV per-ecosystem archives come from the public OSV bucket (validated as zip files with advisories, 2 GiB cap each); the Trivy database comes from running the digest-pinned Trivy image once with `image --download-db-only` (read-only root, all capabilities dropped, the operator's UID, temp files kept in the on-disk staging area). Each tool directory is staged and replaced atomically.
- `ScannerDatabaseManifestV1` (`manifest.json`): per-file SHA-256 and size, upstream build time (OSV `Last-Modified`, Trivy `metadata.json UpdatedAt`), fetch time, per-database and manifest digests.
- `verify`: rehashes every file, refuses additions, removals, modifications and edited manifests, and reports age and a stale flag (default 7 days).
- `MountFor(root, tool)`: the read-only `/db/<tool>` mount plus `--cache-dir /db/trivy` or `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv`.

Database files are world-readable public data; Docker Desktop cannot bind-mount below a restrictive directory, so 0755/0644 is used.

## Integration

- `executor.Config.database` reads the root only from operator configuration (`DatabaseRoot` or `AEGIS_SCANNER_DB_ROOT`), requires a clean absolute path, runs `Verify` and `MountFor`, and refuses to launch on any failure or when the tool's database is missing.
- The CLI and SDK container profiles (`engineprofile.CreateWithDatabase`) add only the read-only `/db/<tool>` bind and the OSV environment variable; with no database they are byte-identical to before.
- `scanner-guard` switches to `scanevidence.BuildDatabaseInvocation` (Trivy gains `--cache-dir /db/trivy`; OSV argv is unchanged) only for advisory tools and only when that directory exists in the container.
- Receipts carry the optional `advisory_database`. `Normalize` accepts the database invocation only with a well-formed database record, refuses a record whose digest differs from `Expected.Database`, and keeps `completed_stale_db` unless that digest is approved and fresh.
- Pending: the controller must bind the approved database digest into the job's expectations, and `engineauthz` must allow the mount for admitted SDK launches.

## Validation

Unit tests cover fetch layout, atomic install, verification, tampering, forged manifests, stale reporting, mount helpers and refusal of invalid archives, path-like ecosystems and unpinned images. `tests/integration/scanner_db_acceptance.py` (`docs/evidence/scanner-database-acceptance.json`) fetched real OSV (npm, PyPI) and Trivy databases, verified them, and ran both pinned images fully offline under scan hardening: both report CVE-2021-23337 (GHSA-35jh-r3h4-6jhm) for lodash 4.17.20 and not for 4.17.21; tampering is refused. Newer advisories affect lodash 4.17.21, so the "safe" fixture's expected results must change once databases are integrated. `tests/integration/scanner_db_executor_acceptance.py` (`docs/evidence/scanner-database-executor-acceptance.json`) runs both tools through the guarded executor with the database mounted and checks the same advisories. It also checks that a run without a database claims nothing and that a tampered database is refused before launch.
