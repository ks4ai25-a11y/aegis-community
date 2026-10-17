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

A scan receives the verified tree **read-only** at `/db/<tool>` with no network: Trivy is pointed at it with `--cache-dir /db/trivy`, OSV-Scanner with `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv` (`scannerdb.MountFor`). Wiring this mount into the scanner worker's execution paths and recording the database digest and age in scan receipts is in progress in the scanner workstream (ADR 057/068); until then the worker still reports these tools as unavailable.

## Limits

A known-vulnerable version is not proof the vulnerability is reachable in your application. Advisory data changes daily: the bundled "safe" fixture (lodash 4.17.21) is now affected by advisories published after it was chosen.
