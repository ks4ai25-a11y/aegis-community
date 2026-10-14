# Scoped scanner cleanup-context reader

This operator-only identity reads controller-recorded scanner launch/workspace metadata. It is separate from scanner workers and browser owners. It cannot claim or execute jobs, acknowledge receipts, stop/remove containers, modify workspace leases or release dispatch admission.

## Enrollment and probe

Provision an owned canonical mode-0700 credential directory. Choose the exact engine and registry digests from an operator-reviewed launch context. Digests identify the original local engine/namespace; they are not paths or evidence that either is currently safe. New enrollment uses a new ID, lifetime of 1–1440 minutes and a new exclusive mode-0600 file:

```sh
aegisctl scanner-verifier enroll VERIFIER_ID MINUTES ENGINE_DIGEST REGISTRY_DIGEST ABSOLUTE_PRIVATE_FILE
aegisctl scanner-verifier probe ABSOLUTE_PRIVATE_FILE
aegisctl scanner-verifier revoke VERIFIER_ID
```

Run the controller CLI through the established local operator channel. `AEGIS_SCANNER_SOCKET` must identify the owned mode-0600 Unix socket inside an owned mode-0700 directory. The dashboard has no enrollment operation. Probe reads credentials internally and prints only identity metadata. Revocation is idempotent, denies later verifier calls and leaves worker identities and dispatch holds unchanged.

At most four active observer identities per owner and 100 retained identities globally are admitted. Expired/revoked IDs cannot be reused. Scope, expiry and token-hash fields are immutable; revocation cannot be reversed. Enrollment and its audit append commit together. Capacity exhaustion refuses new enrollment rather than silently discarding history. Archive/rotation controls remain unfinished.

## Read an exact job context

Build the research CLI and guards with `make research-build`. On Linux/macOS with the same private-socket/credential ownership boundary:

```sh
bin/aegis-research verifier-context SOCKET CREDENTIAL_FILE OWNER VERIFIER_ID ENGINE_DIGEST REGISTRY_DIGEST CANONICAL_AEGIS_SOURCE_ROOT JOB_ID
```

The source root supplies the bounded operator-provisioned scanner lock. The client pins expected owner, verifier ID, engine, registry and lock digest; validates canonical bounded responses; rereads credential files; and refuses redirects or stale/mismatched context. Credentials and job lease capabilities never enter the output.

The separate private operations are POST `/internal/v1/scanner/verifier/identity` with `{}` and `/internal/v1/scanner/verifier/context` with an exact job_id. No cookies, Origin, query parameters, content encoding, additional/duplicate fields, non-POST method or worker credential is accepted. Context reads recheck enrollment/scope in the same transaction as dispatch and immutable launch/workspace records. They emit no host paths, source bytes, raw scanner output, token hashes or lease capabilities.

At least one matching schema-1.1 launch and workspace reservation is required. Legacy, prelaunch/incomplete-scope and unknown records remain unavailable. A workspace reservation with no launch is retained in a partially launched suite's context; it is not interpreted as absent. Cancellation is reported separately from job terminal state. The original absolute deadline and recorded lease expiry remain visible; neither establishes that a process stopped.

## Meaning of the result

ScannerCleanupContextRecordV1 has a canonical context digest. It is a point-in-time metadata snapshot, not a signature or cleanup receipt. controller_metadata_only and cleanup_required remain true; cleanup_confirmed, active_workspace_leases_excluded and late_start_excluded remain false. File-based sandbox observations from ADR 039 keep their original false authority flags. An offline copy of this JSON is not a reusable authorization capability.

The real-tool/native private-channel tests do not prove that a dedicated background worker can pair with the deployed Compose UID-10001 socket from another host/kernel. That deployment remains unfinished. Independent engine/registry inspection, pending-engine-request exclusion, active leases/incomplete allocations, bound cleanup evidence and atomic release are still required. Containers do not satisfy the v4 D6 boundary for arbitrary repository/patch execution.

## Schema 13 upgrade

Use a private consistent database backup before initializing the new image. Migration 13 adds only the verifier-enrollment ledger, scope immutability and monotonic revocation triggers; migration checksums 1–12 are preserved. Align the named init, controller, deployer and verifier services to the rebuilt shared image. Shared source changes can change guard hashes even when entrypoint behavior stays the same; compare both native and packaged guard builds and upgrade worker packages together. Historical records keep their original hashes and are not reinterpreted as fresh authority.
