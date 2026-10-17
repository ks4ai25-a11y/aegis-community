# Offline vulnerability databases (OSV-Scanner and Trivy)

Scanner jobs run with no network, so OSV-Scanner and Trivy need a vulnerability database provisioned ahead of time. Without one they report a tool error instead of pretending a dependency is clean.

## Fetch (the only step with network access)

```sh
(cd alpha && go build -o ../bin/aegis-scanner-db ./cmd/aegis-scanner-db)
bin/aegis-scanner-db fetch /srv/aegis/scanner-db                       # OSV for 8 ecosystems + Trivy
bin/aegis-scanner-db fetch /srv/aegis/scanner-db --tools osv_v2 --ecosystems npm,PyPI
```

- **OSV**: per-ecosystem `all.zip` archives from the public OSV bucket (`osv-vulnerabilities.storage.googleapis.com`), stored in the layout OSV-Scanner v2 reads (`osv/osv-scalibr/<ecosystem>/all.zip`).
- **Trivy**: the digest-pinned Trivy image from `tools/scanners.lock.json` runs once with network to download its database into `trivy/db/`.

Both sources are free; no account is needed. Each fetch is staged and installed atomically, and `manifest.json` records every file's SHA-256 and size, the upstream build time, the fetch time and a manifest digest. Expect roughly 1.5 GB for npm + PyPI + Trivy; the full default ecosystem list is larger.

## Verify

```sh
bin/aegis-scanner-db verify /srv/aegis/scanner-db             # rehash everything, report age
bin/aegis-scanner-db verify /srv/aegis/scanner-db --json --max-age 72h
```

Any added, removed or modified file, or an edited manifest, fails verification. Databases older than `--max-age` (default 7 days) are reported **STALE**; refresh them with `fetch`.

## How scans use them

Set `AEGIS_SCANNER_DB_ROOT` to the database directory for the operator scan commands (`aegis-research scan-offline`, worker commands). Optionally set `AEGIS_SCANNER_DB_MAX_AGE_HOURS` (default 168). Before each OSV-Scanner or Trivy run the executor rehashes the database and refuses to launch if verification fails. Then the scan receives the verified tree **read-only** at `/db/<tool>` with no network: Trivy is pointed at it with `--cache-dir /db/trivy`, OSV-Scanner with `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv`.

```bash
AEGIS_SCANNER_DB_ROOT=/srv/aegis/scanner-db bin/aegis-research scan-offline trivy /path/to/repo "$PWD"
```

The scan receipt records `advisory_database`: manifest and database digests, upstream build time, age in hours, the stale flag and the mount path. A result counts as current (`completed`) only when the job's approved database digest matches and the database is fresh. Otherwise it stays `completed_stale_db`. The controller does not bind an approved digest yet, so results it ingests are still `completed_stale_db`. The admitted SDK engine path also refuses database mounts until its mount allowlist is extended. Without `AEGIS_SCANNER_DB_ROOT`, the tools run as before and report no result.

Recorded run: `docs/evidence/scanner-database-executor-acceptance.json`. Both tools report CVE-2021-23337 / GHSA-35jh-r3h4-6jhm for lodash 4.17.20 and not for 4.17.21, a run without a database claims nothing, and a tampered database is refused before launch.

## Limits

A known-vulnerable version is not proof the vulnerability is reachable in your application. Advisory data changes daily: the bundled "safe" fixture (lodash 4.17.21) is now affected by advisories published after it was chosen.
