# ADR 021: Durable offline scanner request state

Status: controller persistence component implemented. Worker dispatch, receipt ingestion, authenticated scanner endpoints and console journeys remain unfinished.

The operator scanner executor does not constitute controller job orchestration. A new scanqueue package and additive SQLite migration 4 provide the request-state foundation for that required architecture. Deployed migrations 1–3 remain unchanged. Scanner state is separate from WAF fixture research state; offline scanner requests do not consume or borrow dynamic HTTP scope grants.

An accepted request binds its owner, connected repository ID, application, exact current application-map digest, repo_offline mode, a sorted unique selection from the six supported static tool IDs and a bounded per-tool timeout. The tool-lock digest comes from trusted queue configuration, not request data. No path, URL, shell, argv or network profile is caller-selectable. Future dispatch must resolve the same reviewed lock and recapture the exact source map before execution. A registered map is not proof that current mounted bytes still match it.

Enqueue checks repository ownership and current map identity in the same SQLite transaction as job insertion and the audit record. The immutable map foreign key retains the declared source identity. Idempotency is scoped by owner and binds the request including tool-lock digest; changing tool selection, timeout or pins cannot silently reuse a key. The request hash also binds the owner. Stored requests are rehashed when read and checked against relational repository/application/map fields; corrupt or reassigned payloads are refused. Input slices are copied before retention.

Queued cancellation and its audit record commit together. Running-state cancellation records a request rather than reporting that an external container has already stopped; worker interruption and confirmed cleanup are still required. This component has no worker claim or success transition and cannot fabricate completed scanner evidence. A fifteen-minute queue expiry is recorded; expiry enforcement must be part of dispatch before an executor receives a lease.

Admission is bounded to twenty queued/running requests per owner and one thousand retained requests globally. Lists return at most one hundred owner-scoped records. No automatic evidence deletion is introduced to evade this budget; retention and archival need an explicit policy. The database contains only typed request metadata, never source content, raw scanner matches or credentials.

Tests use real SQLite and provisioned repository registration. They cover concurrent idempotency, restart persistence, owner isolation, map/pin changes, corrupt payload refusal, caller-slice mutation, active and retained-history budgets, audit failure rollback for enqueue/cancel, and migration from the prior three-version database while preserving checksums and existing state.

This is an internal component, not an available scanner HTTP feature. Trusted startup lock provisioning, authenticated API/generated bindings, isolated worker enrollment, leases/expiry/reconciliation, per-tool immutable receipts, append-only findings, revocation interruption, confirmed workspace cleanup and end-to-end scanner jobs remain necessary. The public controller still has no Docker socket. Neither this migration nor its tests complete v4 D3, D4 or the release gates.

The local upgrade exposed a retained init container running the previous image. That old binary refused migration 4 as designed. Recreating init and all services sharing the controller image restored a consistent deployment; the upgrade guide records this observed failure and corrected sequence.
