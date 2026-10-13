# ADR 017: Atomic research authorization and audit persistence

Status: implemented; local failure-injection and real scoped-job integration acceptance passed. Independent security review remains a release requirement.

The existing WAF research queue previously persisted some scope/job mutations separately from the hash-chained audit append. This could create an authorization or result without its corresponding audit record, or record an approval that never committed. The scanner queue must not inherit that transaction boundary.

Scope draft, exact-digest approval, revocation, enqueue, claim/request reservation, cancellation, lease-expiry reconciliation and terminal report persistence now append their audit record within the same SQLite transaction as their durable state change. An audit insert failure rolls back the entire operation. Idempotent reads do not append a duplicate authorization. Lease heartbeats remain bounded operational updates rather than a new grant of authority.

Claim additionally recomputes the immutable request digest and checks application, scope, fixture and policy identities. It reads and validates the policy document inside the claim transaction before consuming the four-request budget. Corrupted inputs or policies cannot reserve budget or start a worker. Reconciliation is bounded to 200 interrupted/unauthorized jobs per claim and records each affected job individually; uncertain execution is still never retried automatically.

Tests install an actual SQLite BEFORE INSERT trigger that aborts audit persistence. They verify byte-equivalent durable state before/after failed draft, approval, enqueue, claim, cancellation, revocation, finish and recovery operations, including report and report-owner rows. Separate corruption tests verify unchanged request budget and queued attempt count when payload or policy identity is damaged. Existing owner, expiry, cancellation, report-control and stale-lease checks remain required.

This change neither implements durable scanner execution nor grants new target, network, Docker or staging access. The web controller still has no Docker socket. SQLite host administrators can still rewrite the database and audit history; the local hash chain is not an external signature or independent attestation. The signed grant/receipt and independent review requirements remain open.

Evidence: `docs/evidence/research-audit-acceptance.json` records the ten actual SQLite failure/corruption cases and source hashes. `docs/evidence/scoped-jobs-acceptance.json` records real claim/reconciliation audit events and local chain verification after controller SIGKILL. The full controller race suite passed.
