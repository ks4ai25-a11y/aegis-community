# Private recovery bundles for the reference demo

The local CLI can capture and verify a private bundle of the current controller database, exact persisted gateway configuration, and pinned scanner lock, then restore into a new offline directory. Supported scope is the current `demo-http-v1` reference deployment, product `0.1.0-alpha.1`, database schema 13, Linux/macOS Unix ownership semantics. Other gateway templates, database versions, missing tool locks, inconsistent policy state and unfinished policy applies are refused. This does not complete GATE-11: a second clean machine, upgrade/failure drills and release acceptance remain outstanding.

```text
aegisctl backup bundle /absolute/owned/export/bundle --json
aegisctl backup verify /absolute/owned/export/bundle --json
aegisctl backup restore /absolute/owned/export/bundle /absolute/owned/recovery --confirm sha256:EXACT_BUNDLE_DIGEST --json
```

Replace the confirmation with the exact `bundle_digest` from the verified receipt. Run as the identity owning the state. `AEGIS_DATA` selects the database directory, `GATEWAY_POLICY_ROOT` selects the directory containing `active.Caddyfile`, and `AEGIS_SCANNER_LOCK` selects the independently trusted lock (packaged default `/opt/aegis/scanners.lock.json`). New destinations need existing owned parents without group/other writes. Paths must be absolute and canonical. Existing destinations are never replaced. Restore cannot target the bundle or its children. No running service is stopped, switched or activated by these commands.

Bundles contain exactly `state.db`, `active.Caddyfile`, `scanners.lock.json`, `manifest.json` and an empty `.lock`. Directories are mode 0700 and files mode 0600. Creation uses a consistent SQLite backup and checks the captured database's migration history, audit chain, full SQLite integrity check, foreign keys and active policy. The gateway file must exactly match the supported rendering of that policy. The manifest binds each artifact's byte count and SHA-256, schema, profile, policy and creation time. Verification requires canonical JSON, an unchanged trusted scanner lock, exact file membership and valid database/configuration relationships. An exclusive lifetime lock refuses concurrent operations. Each command is bounded by sixty seconds; the database is limited to 512 MiB and each configuration file to 64 KiB.

Keep these files private. They include password hashes, capability history, account data and review records. They are not application-encrypted. A checksum provides integrity, not provenance or publisher authenticity: verify the bundle's origin, age and sensitivity using your trusted local records before confirming restoration. Never fetch the trusted scanner lock from an untrusted bundle. Receipts contain no database contents or host paths and always leave publisher-signature verification false.

Restore writes `data/aegis.db`, `gateway/active.Caddyfile` and `tools/scanners.lock.json` under a fresh destination. Before copying database bytes it writes `data/.restore-pending`; normal controller/database-snapshot opening refuses any directory containing that marker. Within the isolated destination, one audited transaction deletes restored sessions, pending invites/consents/handoffs and idempotency entries; revokes app connections, scope grants, scanner workers and cleanup verifiers; cancels queued/running jobs; clears preview/apply authority; and requires review of pending policy drafts. Existing scanner dispatch slots remain `cleanup_required`. Immutable evidence and finding history remain available. The original bundle is unchanged.

Successful completion checkpoints and syncs the database, records its new digest and writes `data/.restore-complete.json` plus `recovery.json` before removing the pending marker. A failed command never reports success. An interrupted process can leave a private incomplete directory; retain its quarantine marker, do not start it or manually remove the marker, and retry into a different new destination. Automated incomplete-restore repair is unavailable. A late sync error can leave a completed directory requiring separate inspection; it is never automatically installed.

For an actual deployment recovery, keep the controller and verifier stopped while selecting restored data and matching policy using an explicit operator procedure. The CLI intentionally supplies no automatic volume replacement or gateway activation. After installation, use a fresh owner login, review the invalidation audit event and recovered inventory, check the gateway's actual revision, and enroll fresh narrowly scoped connections/workers only after review. Scanner cleanup holds must not be released using restored credentials or by deleting dispatch rows.

The opt-in drill `AEGIS_RECOVERY_DRILL=1 python3 tests/integration/recovery_application_acceptance.py` requires locally built demo images and a local Unix Docker endpoint. It allocates a unique Compose project, rejects external/shared resource names and unexpected host mounts before starting, and destroys only its label-checked disposable controller data volume. It restores synthetic state, rejects the old session, checks fresh login/inventory/cancelled scans and the gateway revision, then removes only its own resources. It does not execute arbitrary application code. The existing demo stays separate. The observed drill runs on one engine and is not proof of second-host recovery or independent security review. Command receipts retain `live_activated: false` and `application_restore_verified: false`; the separate drill report records its narrower application observation.

See [ADR 044](../architecture/adr/044-bound-recovery-bundles.md) and [recovery evidence](../evidence/recovery-bundle-acceptance.json). Native synthetic CLI checks and namespace refusal tests run in `make test`; the disposable application drill runs in trusted-demo CI.

For the packaged Compose demo, the web controller deliberately has no gateway-policy mount. Run the bundle CLI through the existing operator init service, which already has both required volumes and no network:

```sh
docker compose -f deploy/compose.demo.yaml run --rm --no-deps --entrypoint aegisctl init backup bundle /var/lib/aegis/operator-bundle-UNIQUE --json
docker compose -f deploy/compose.demo.yaml run --rm --no-deps --entrypoint aegisctl init backup verify /var/lib/aegis/operator-bundle-UNIQUE --json
```

Choose a new suffix for each capture. These commands retain sensitive bytes inside the controller data volume. Running bundle capture inside the web controller fails because the gateway file is unavailable there; do not grant it another mount to bypass that boundary. The restore command is for a separate fresh offline destination; never copy restored bytes over a running controller volume.

Restoring current state also removes the immutable scanner engine/registry host binding. Historical binding audit and scan records remain; restored workers/verifiers stay revoked and dispatch cleanup holds remain. Provisioning another host cannot bypass a retained hold.

The separate scanner journal root/namespace binding is also removed during restore. Both previous host approvals become unavailable, historical launch/audit records remain, and cleanup admission stays held. Rebinding or initializing another namespace cannot bypass a restored hold.

Restore also removes the selected scanner-broker binding and revokes worker enrollment. Its historical approval and scan records remain; cleanup holds are not released by restoring or selecting another broker.
