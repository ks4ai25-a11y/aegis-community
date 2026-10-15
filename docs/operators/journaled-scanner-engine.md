# Journaled scanner engine backend

This is an experimental local operator backend for fixed, read-only offline scanners. Aegis remains unfinished. The backend does not release controller cleanup admission, establish an exclusive engine broker, or provide the disposable VM boundary required for arbitrary repository/patch execution.

## Operator commands

Build with `make research-build`. Run as a non-root Linux/macOS operator against a local Unix Docker endpoint. The existing endpoint selector resolves the chosen local engine once; subsequent SDK requests use that explicit endpoint, fixed API 1.55 and a bounded direct Unix transport. Remote endpoints, proxy use, redirects, ambient SDK API-version overrides and image pulling are unavailable. An unsupported daemon/API fails closed.

Use absolute canonical paths. The journal is a private persistent directory owned by that operator, outside the disposable workspace registry/session. Its existing parent must resolve canonically. The backend creates the directory with mode 0700 and records with mode 0600. Choose one persistent journal for the supported operator; a different journal is not a way to resolve an uncertain previous run.

```text
aegis-research scan-offline-journaled SCANNER CANONICAL_REPOSITORY CANONICAL_AEGIS_SOURCE_ROOT CANONICAL_JOURNAL_ROOT

aegis-research worker-once-journaled SOCKET PRIVATE_WORKER_CREDENTIAL_FILE OWNER CANONICAL_AEGIS_SOURCE_ROOT CANONICAL_ASSET_ROOT CANONICAL_JOURNAL_ROOT

aegis-research engine-journal-status CANONICAL_JOURNAL_ROOT ENGINE_DIGEST
```

The worker command still requires valid operator enrollment, provisioned source consent and an authorized controller claim. It runs one queued suite and exits. The offline command uses the existing local snapshot/guard path. Existing commands without `-journaled` retain their prior backend; no background service or GUI pairing is implied.

The status command locks and validates an **existing** journal. It does not contact Docker, create/repair files, settle requests, remove source or release admission. Missing, unsafe, busy, torn or mismatched state is refused. Its engine digest must match the enrolled local journal; it is metadata, not a credential.

## Request lifecycle and uncertainty

Before a create/start/remove RPC, the backend exclusively writes and fsyncs a digest-bound intent. It records a response only after receiving a complete bounded daemon response with the expected status and container identity. Create responses must contain one complete JSON document; an incomplete, oversized, malformed, redirected or unexpected response remains uncertain. A tool exit, cancelled caller or absence query cannot acknowledge that intent.

Attach is registered before start, with bounded HTTP upgrade headers and separately bounded multiplexed stdout/stderr. A next-exit wait is acknowledged before start, so a fast scanner cannot lose its result to automatic removal. After a known exit, a read-only removed-state wait allows Docker's asynchronous automatic removal to finish before the tracked exact-ID remove/absence check. A conflicting or incomplete remove response remains quarantined; it is not silently retried as a new mutation.

Cancellation closes and joins readers; cleanup has a separate ten-second budget. If a start response remains unknown, the backend refuses a following remove mutation rather than pretending the start has settled. The fixed guard still enforces its original absolute deadline. Source/guard workspaces remain preserved when cleanup is unconfirmed.

A kernel lock excludes concurrent writers in the selected journal namespace. Restart validates the entire bounded hash-linked history. Unanswered mutations and unfinished lifecycles refuse another attempt. Limits are 1,000 retained attempts, 16 MiB total records and 4 KiB per record; ordinary daemon response bodies/headers are bounded at 64 KiB. There is no retention pruning or trusted reconciliation/reset command yet. Preserve uncertain journals and bound workspaces for future trusted recovery; changing/deleting a directory or observing absence does not authorize controller release.

A settled journal observation still explicitly reports:

```json
{
  "controller_gate_binding_verified": false,
  "all_engine_writes_mediated": false,
  "cleanup_release_authorized": false
}
```

The records contain namespace/engine/configuration digests, container identity, operation/status and timestamps. They exclude credential bytes, host paths, raw scanner output and source snippets. This is local bookkeeping under operator-host trust. It does not authenticate a separate verifier or exclude direct Docker access, another journal, older CLI paths, incomplete workspace allocation or active leases.

## Observed evidence and remaining work

[ADR 042](../architecture/adr/042-journaled-engine-sdk-lifecycle.md) and [acceptance evidence](../evidence/scanner-engine-journal-acceptance.json) record response-fault, symlink/FIFO/hardlink, process-crash, cancellation and actual pinned-image tests. Actual stale-database/tool-error classifications are preserved; zero findings does not establish safety. The stopped-container profile comparison is an observation, not authority.

Required follow-on work includes controller-provisioned journal/gate binding, exclusive mediation of all engine writes, independent verifier deployment, active-lease/incomplete-allocation checks, trusted reconciliation and separately authorized atomic cleanup release. Deployed UID/socket pairing, background workers, offline database provisioning, VM isolation, desktop AI/MCP/provider testing and the remaining v4/H7 release gates remain unfinished.
