# Scanner authorizer enrollment

This is the enrollment foundation for [ADR 057](../architecture/adr/057-scanner-allocation-fencing-and-cleanup-release.md). It does not yet admit engine mutations, resolve unknown allocations or release cleanup holds. Existing `serve-bound` still requires its separate read-only observer credential; an authorizer credential is not a replacement for that observer.

After connecting an owned provisioned repository, a local unprivileged operator can enroll one active authorizer per owner:

```text
aegisctl scanner-authorizer enroll ID MINUTES ENGINE_DIGEST REGISTRY_DIGEST POLICY_DIGEST ABSOLUTE_PRIVATE_FILE
aegisctl scanner-authorizer probe ABSOLUTE_PRIVATE_FILE
aegisctl scanner-authorizer revoke ID
```

`MINUTES` is 1–1440. Scope values must be SHA-256 digests. The policy digest identifies the intended exact serving policy; enrollment records that identity and does not approve its content or establish engine exclusivity. Actual daemon/controller admission integration is still required before it can be used for writes. The private probe needs `AEGIS_SCANNER_SOCKET` pointing to the configured owned Unix socket.

Credential files must be new files under a canonical operator-owned mode-0700 directory. Delivery uses mode 0600, refuses overwrite and substituted paths, syncs the file and directory before committing enrollment, and never prints the credential. Failed delivery rolls back enrollment and removes only the file it created. Keep credentials outside repositories and public evidence directories. No browser owner endpoint enrolls this role.

The private channel exposes only `/internal/v1/scanner/authorizer/identity`. Worker and verifier credentials cannot use it. Authorizer credentials cannot claim, renew, finish or read verifier context. `admit`, `complete`, `release` and `reset` are unavailable. Identity responses describe scope and expiry; they are not mutation grants. Revocation is retained, audited and idempotent; it does not change the worker's dispatch state. Existing IDs cannot be reused, and at most 100 enrollment records are retained. Replacement/recovery must resolve any outstanding obligations before a future admission implementation can use the replacement.

Migration 014 adds immutable authorizer scope and monotonic active-to-revoked state. Earlier migration checksums and existing observer enrollments remain intact; migration creates no authorizer or dispatch authority. Upgrade controller/init binaries together after capturing a private consistent backup. Recovery accepts verified version-13 through version-16 bundles, checks their exact matching migration prefix, preserves offline schema during restore, and revokes authorizers when present from version 14 onward. Version16 also revokes selected authorizer bindings and closes allocation generations while retaining unresolved mutation obligations. A restored version-13 database gains an empty authorizer table only during an explicit normal upgrade. Scanner cleanup holds remain held in either version. Snapshot validation reads one row beyond the supported migration prefix, so a later unsupported version cannot be hidden by a fixed row limit.

Native CLI acceptance uses fresh private synthetic state. Role, private Unix channel, migration preservation, authority invalidation and legacy restore checks run in `make test`. These checks do not establish controller mutation fencing, independent engine reconciliation, repeated-scan operation, VM isolation or full v4 release acceptance.
