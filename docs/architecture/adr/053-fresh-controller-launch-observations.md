# ADR 053: Fresh controller observations of an approved live scanner launch

Status: implemented read-only precondition; daemon consumption and durable engine allocation authorization remain unfinished.

## Decision

Extend the existing private cleanup-observer channel with `POST /internal/v1/scanner/verifier/live-launch`. The request contains only an exact `aegis-scan-<32 hex>` name and a new 128-bit challenge. It is not served by the browser API and accepts no worker lease token, owner override, filesystem path, command, image or daemon endpoint. It uses the existing purpose-separated, expiring, owner/engine/registry-scoped observer enrollment. Worker credentials cannot read it; observer credentials still cannot claim, renew, finish or release work.

Within one SQLite transaction, authenticate the observer, locate the exact immutable launch owned by its scope, read original workspace/launch context and require the full current engine/journal/broker approval chain. The observation requires a guarded revision 1.2 launch bound to the configured journal identity, the selected enrolled worker, a running uncancelled job, active unexpired dispatch, original deadline, current guard set and current approved repository map/tool lock. Missing, corrupt, expired, cancelled, revoked, rotated, legacy or mismatched state is refused. Context cancellation is checked and expiry is rechecked before returning. No lease token/hash is selected or returned, no lease is renewed, no audit record is added, and the dispatch slot is never released by this read.

The bounded digest-wrapped response echoes the challenge and includes original scoped metadata and immutable bindings. `live_lease_observed` and `controller_metadata_only` are true; `engine_write_authorized` and `cleanup_release_authorized` are always false. The alpha observer client creates a new cryptographic challenge per call, validates all nested digests and binding relationships, rejects replies for another name/challenge, checks observation freshness and residual lease/deadline, rereads the private capability, and applies the existing strict JSON and Unix channel boundaries. Requests/replies have generated Draft 2020-12 schemas and Go/Python/TypeScript bindings. Checked-in examples are constructed synthetic data, not runtime observations.

## Related contract corrections

Cleanup-context reads used a literal revision 1.1 check despite the shared validator/schema supporting guarded revision 1.2. Use the shared guarded-revision predicate so current journal-bound launches can be observed without dropping their journal fields. Live-launch reads additionally require revision 1.2 and the full current binding chain; historical context compatibility does not become live execution authority.

The preflight schema previously accepted only the raw Unix backend string. Add the implemented `mtls-unix-sdk-1.55` value while retaining refusal of unknown backends. The private HTTP channel also rejects encoded-path aliases before routing. No database migration is needed.

## Authority limits and next integration

This response describes a transactional snapshot at its observation time. It may become stale immediately afterward; a concurrent revocation can commit after the snapshot. A nonce-correlated unkeyed digest is not a transferable grant or independent attestation. A consumer must not turn this read into a permanent allow, a release capability, or a claim that all engine writes are mediated.

The daemon plugin has not yet consumed this endpoint. Durable allocation admission, mutation intent correlation, source/guard byte verification, cancellation/revocation fencing and independent cleanup reconciliation/release remain required. Work admitted before a cancellation may still reach the engine and must remain represented as possible allocation until independently reconciled. Existing standalone and packaged TLS experiments retain their conservative false mediation/release flags and second-job hold. Host/controller clocks and privileged host components remain trusted. Full v4 and public beta remain NO-GO.

## Validation scope

Tests challenge expiry during a read, revoked/expired enrollment, cancellation, held/terminal dispatch, wrong scope, corrupted/missing approval chain, changed repository/lock/guard identity and cancelled contexts. They verify no lease/audit/admission mutation, no token/hash/path disclosure, real alpha-client/controller interoperability over the actual private Unix socket, fresh challenge correlation, strict malformed reply refusal, purpose-separated HTTP authentication and browser/encoded-path rejection. Schema validation covers constructed examples, authority-flag refusals and both accepted preflight backend values. These are automated reference checks, not independent sign-off or daemon enforcement proof.

`docs/evidence/live-launch-validation.json` records 129 repeated controller/channel pass events, 45 repeated client pass events, real Unix-channel interoperability, synthetic schema validation, full source checks, static analysis and all four successful hosted jobs at the cited source revision. It contains test statuses/source references only. The retained demo was privately backed up and its matching components upgraded with readiness, Observe mode and integrity checks verified. Runtime backup/installation records remain private.
