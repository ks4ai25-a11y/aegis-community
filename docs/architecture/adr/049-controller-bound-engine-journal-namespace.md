# ADR 049: Bind journal root and namespace to controller launch authority

Status: implemented experimental scope binding; independent cleanup release remains unavailable.

## Decision

Extend ADR 048's immutable engine scope with a separate immutable journal binding, referring to the original engine binding digest. The journal record binds owner, canonical journal-root/UID digest, journal namespace digest and creation time. It does not replace or weaken the existing engine/registry approval. A local `aegisctl scanner-engine bind-journal ROOT_DIGEST NAMESPACE_DIGEST` operation requires a valid existing engine approval and no dispatch slot on initial provisioning. Exact repeat is read-only/idempotent; replacement, reset, cross-owner scope, missing/corrupt parent scope and initial provisioning over active/held dispatch are refused. The record and audit commit together. No database migration or browser mutation endpoint is added.

A finite authenticated private read returns the bounded canonical record, rechecking enrollment inside its transaction. Client validation checks owner, parent identity, UTC creation order, hashes, canonical wire bytes and current time. Restore removes both host scope settings while preserving history and cleanup holds; it never treats a new namespace as recovery.

The packaged `worker-once-bound` now requires both records before claim. It checks its configured journal root digest, reads the existing private journal under its lock, checks approved namespace/engine and refuses unfinished/unresolved state. It also retains the original engine/registry preflight. Missing, busy, changed or inconsistent scope refuses before source allocation or claim.

## Execution and history

New journal-bound launches use document revision 1.2, with explicit journal binding and namespace digests in the plan. The controller validates them against the immutable scope in the launch transaction, so an older client omitting these fields cannot downgrade a configured installation. Unconfigured legacy experiments retain revision 1.1. Readers accept valid historical revisions, but reject mixed revision fields; schema 1.2 requires both journal hashes. Receipts and observer context still refer to the original immutable launch. Typed contracts, generated clients and cleanup-context schemas include this revision without upgrading legacy claims.

After source capture and controller registration, the executor reopens **only existing** journal state, acquires its lifetime kernel lock, rechecks approved root and namespace and only then begins a durable mutation intent. Missing state is never recreated by this path. This closes substitution between preclaim observation and execution. An open root handle anchors records if its pathname changes; another fresh namespace cannot inherit approval. Busy, incomplete, pending, replaced or corrupted state remains refused. Uncertainty preserves source/workspace records and dispatch admission.

`engine-journal-init CANONICAL_ROOT` is an explicit local operator command that reads the configured engine and initializes or reuses only a validated empty namespace. Existing directories use the existing-only opener, so missing lock/identity metadata is never repaired. It returns proposed engine/root/namespace hashes with authority flags false. It never pulls, claims or performs daemon writes. A used journal is refused and retained. Root identity includes canonical path and UID; calculate provisioning inside the intended packaged identity and actual mirrored workspace path.

## Acceptance boundary

Focused tests cover immutable/replayed/restarted and concurrent provisioning, transaction rollback, prior/future timestamps, corrupt/missing parent state, private channel refusal, credential revocation, schema downgrade and changed launch identity. Executor tests challenge replacement at the original path, missing roots/identity, wrong root digest/namespace, busy lifetime locks and incomplete configuration, requiring zero daemon RPCs on refusal. Observer/client tests preserve false cleanup flags under revision 1.2. Restore removes both bindings without releasing dispatch.

The isolated packaged fixture moves only its own empty, never-attempted test journal aside, initializes a fresh namespace at the approved path, proves the bound worker refuses it without claiming, then restores the original empty approved fixture namespace. This is test fault injection, not an operator reset/recovery facility. It subsequently executes real pinned tools, checks every exported launch is revision 1.2 and matches approval, refuses reinitializing the used journal, observes settled local records and confirms the next job remains held. Fixture cleanup is separate and verified for only nonce-owned resources; unknown execution is preserved.

## Limits

Local operator provisioning and checksum consistency do not attest the host or prevent a privileged operator cloning/tampering with state. This is not an exclusive all-engine-write broker: old native paths, direct daemon access and incomplete allocations still need independent mediation. Library journal observations have no authenticated controller context and retain false gate-binding/exclusive-origin/cleanup-release flags even when the worker compares a provisioned scope. Active workspace leases and queued late starts are not independently excluded. No cleanup verifier, reconciliation/reset or release endpoint is introduced. VM isolation, advisory databases, proof/remediation lifecycle, AI/MCP, independent installation/signatures/security review and full v4/H7 acceptance remain unfinished; public beta stays NO-GO.

## Observed local evidence

`docs/evidence/journal-binding-acceptance.json` records 75 controller and 201 worker/executor repeated race test events, full final source tests, controller/alpha vet, actual schema checks and historical revision compatibility. `docs/evidence/journal-bound-worker-acceptance.json` records the actual six-tool package run and its nonce-scoped resource cleanup. Both deterministic guard identities are captured and the worker/controller packages agree. Missing advisory databases remain errors; findings remain T0.

Review found that using the general journal opener for explicit initialization could allocate a missing lock in an existing directory before rejecting it. Initialization now creates only a new directory or uses the existing-only opener, and both unit and packaged partial-directory checks prove no missing files are repaired. This correction does not reset any attempted journal or release admission.
