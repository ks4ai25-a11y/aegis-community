# Local demo upgrades with a persistent database

All services using the controller image must move together. A retained init container has its own image identity; rebuilding a tag and replacing only the controller does not replace init. An older init binary correctly refuses a database migrated by a newer controller. This was observed during the migration 4 crash test and resolved by recreating init from the same image.

Use these commands from the repository root for the current local demo. They affect only the named Aegis compose project. Stop submitting jobs and wait for active jobs to finish before the service restart. Preserve an online backup as sensitive local owner state using a fresh filename:

```sh
docker compose -f deploy/compose.demo.yaml exec -T controller aegisctl backup /var/lib/aegis/pre-upgrade-unique-name.db
docker compose -f deploy/compose.demo.yaml build init
docker compose -f deploy/compose.demo.yaml up -d --no-deps init
docker wait aegis-community-init-1
```

The init exit code printed by docker wait must be zero before continuing. Recreate the other services sharing that exact image, then check persistence and readiness:

```sh
docker compose -f deploy/compose.demo.yaml up -d --no-deps deployer verifier controller
docker compose -f deploy/compose.demo.yaml exec -T controller aegisctl doctor
python3 tests/integration/repository_acceptance.py
python3 tests/integration/scoped_jobs_acceptance.py
```

The scoped-job acceptance includes an intentional controller SIGKILL and tests lease expiry without a false success. Run it only against this bundled synthetic demo. A failed acceptance result remains a failure until the cause is corrected and an actual rerun passes.

Do not downgrade binaries against a migrated database, delete migration records or edit checksums to bypass incompatibility. Restore requires a matched earlier release and its protected consistent backup; independent upgrade/restore acceptance and release signing remain open gates. This procedure is the current local demo upgrade, not a complete release manager or arbitrary installation guarantee.
