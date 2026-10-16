# Support diagnostics

`aegisctl diagnostics` prints a support bundle you can share when asking for help. It opens the database read-only and contains only:

- product and database schema versions, SQLite quick-check result, size and audit-chain consistency;
- the active revision digest and **counts** (registered sites, sites per mode, TLS and rate-limited sites, exclusions, trusted proxy ranges) and whether policy changes are frozen;
- telemetry counters (retained, dropped, rejected), open incidents per detector, job counts per state;
- counts of active authorities (owners, sessions, connector credentials, scanner workers, scope grants);
- the latest live canary outcome;
- a digest of the bundle itself.

It never includes events or request metadata, incident evidence, host names, origins or routes, owner identities or sessions, credentials, tokens or keys, policy or finding contents, or repository source.

```sh
docker compose -f deploy/compose.demo.yaml exec controller aegisctl diagnostics          # readable
docker compose -f deploy/compose.demo.yaml exec controller aegisctl diagnostics --json   # one line
```

Nothing is sent anywhere; you decide whether to share the output.
