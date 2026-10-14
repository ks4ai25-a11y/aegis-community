# ADR 041: Separate scoped cleanup-context reader

Status: scoped metadata-reader identity implemented and locally verified; no cleanup-release authority.

## Decision

Introduce a local-operator-enrolled scanner-verifier identity, separate from worker credentials, job lease capabilities and browser sessions. Its current role is scanner-cleanup-observer. Scope binds one owner, original engine digest and workspace-registry digest, with bounded lifetime and enrollment counts. Enrollment/revocation is local CLI only, audited atomically, and credentials are delivered exclusively to an owned private file. Worker and verifier token hashes have distinct namespaces; neither role can call the other's operations.

Two finite POST operations on the existing private Unix channel expose verifier identity and bounded controller context for an exact job. The controller rechecks live verifier scope inside the same read transaction as dispatch/workspace/launch records. Context contains no credential, lease capability/hash, host paths, source bytes or raw scanner output. Each record is revalidated against owner/job/request/map, original deadline, scoped engine/registry and recorded guard identity. At least one matching workspace and launch are required; prelaunch/legacy/unknown-scope cases remain unavailable rather than producing an empty cleanup proof.

The returned canonical digest identifies a point-in-time metadata snapshot. Its metadata-only and cleanup-required flags are true; cleanup-confirmed, active-workspace-lease-exclusion and late-start-exclusion remain false. An authenticated controller response authenticates metadata origin under the local-host trust model, not engine state, filesystem absence or process termination. Existing untrusted-file sandbox observations keep their false authority flags.

The scanner-side client pins expected owner, verifier ID, engine, registry and tool-lock identity; uses only the private Unix socket; rechecks credential/socket files; rejects redirects, oversized/duplicate/unknown/noncanonical JSON and mismatched record context; and cannot claim/execute/finalize jobs. No new route is mounted on the public dashboard. Context reads do not mutate job, dispatch or filesystem state.

## Required checks

Challenge worker/verifier/owner role confusion, cross-owner and changed scope, revocation/expiry races, existing credential files, directory/symlink/FIFO refusal, transaction/audit rollback, enrollment budgets, migration preservation, legacy and incomplete context, corrupt or inconsistent records, private-channel framing and hostile client responses. Run actual parser and pinned-scanner fixture journeys through this distinct identity. Verify local CLI delivery/probe/revocation without reading or logging credential bytes.

## Remaining execution work

A separately provisioned engine operation boundary, durable pending-request tracking, registry/lease exclusion, incomplete-allocation handling, verified cleanup receipt and atomic admission release are still required. Native fixtures do not establish deployed background worker pairing. Unknown or timed-out Docker requests must not become absence proof. Arbitrary repository/patch execution still requires the disposable VM/isolated-host boundary from v4 D6. No reusable-worker or release-gate completion claim follows from this reader.
