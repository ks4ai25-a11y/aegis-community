# ADR 057: Scanner mutation admission and confirmed cleanup release

Status: design for implementation. No release endpoint, new capability or migration is enabled by this document. Scanner admission remains held after a dispatched job.

## Problem

The permanent `cleanup_required` hold prevents repeated scanning. Removing it after a worker reports success, a local journal settles or an observer sees no container would permit a previously admitted create/start to complete after release. ADR 053/054 observations are read-only snapshots, and ADR 055 packages those preconditions; none supplies durable mutation admission or cancellation fencing.

## Decision

Release needs a controller-owned mutation ledger, a distinct authorizer capability and independent engine reconciliation. Keep worker, broker, authorizer and observer roles separate. Existing `scanner-verifier` enrollment remains read-only; extending its permission would silently change a deployed capability. A new narrowly scoped authorizer enrollment must bind owner, engine, registry and serving policy, expire and revoke monotonically, and be separately provisioned. Never accept worker credentials on this channel.

Reserve migration 014 for this work. Preserve all earlier migration bodies and checksums. Before enabling a schema change, update backup/recovery validation, contract generation, restore revocation and supported-version checks together. Restoration must revoke new authorizer capabilities and preserve unresolved mutations and cleanup holds.

### Mutation lifecycle

1. The authorizer validates the exact immutable launch and physical inputs. In one controller transaction, admission rechecks scope, current enrollment and broker binding, active dispatch, original deadline, cancellation and a generation that is still open. Persist an intent before any positive daemon authorization reply. Bind it to the launch digest, exact create descriptor, operation, selected authorizer and generation.
2. A replay with the same immutable identity returns the same admission record. Changed input conflicts. Replay must never mean a second engine call; the local durable journal still refuses duplicate mutation execution. The controller cannot infer that an admitted operation actually reached the engine.
3. The native response callback records the exact successful create identity or completed start/remove response in the plugin journal before acknowledging it to the controller. Completion is authenticated as the original authorizer and matches the original intent. Uncertain responses retain unresolved intent. Expiry, revocation, process death or elapsed time never convert uncertainty to success or absence.
4. Finishing, cancellation or timeout closes admission transactionally before reconciliation. A concurrent admission either commits first and remains an obligation that blocks release, or observes closure and is refused. New starts require admission too. Tracked cleanup removal remains available after cancellation, with its own durable lifecycle.
5. Bound serving fails closed if controller admission or completion cannot be confirmed. Local policy and namespace seals must prevent restarting used state in an observation-only or unbound mode. Existing used journals cannot be relabelled into the new protocol.

The ledger must distinguish request admission, daemon response confirmation and independent observation. These are different facts. A response callback proves only what the trusted local authorizer observed; it is not an independent absence check.

### Independent reconciliation and release

An independently enrolled observer uses its own read-only TLS principal against the original approved engine. It checks exact controller-recorded allocations and bounded exact-name lookups, never a broad worker-selected engine query. A lost create response needs positive resolution of that original name and identity; inability to inspect it preserves quarantine. Engine identity, expected generation and complete immutable launch/workspace membership are part of reconciliation.

Release commits only after admission is durably closed, no admitted create/start/remove remains unresolved, every recorded allocation is positively removed and independently absent, and required workspace cleanup is verified against its original registry identity. Recheck enrollment, generation, immutable evidence membership and every ledger obligation in the same transaction that records cleanup confirmation and deletes the dispatch slot. A stale report or changed membership conflicts. Repeating the same accepted confirmation is idempotent; it cannot free a later dispatch slot.

This ordering excludes late allocation because every allowed mutation leaves an obligation until its actual completion is known, and closed admission prevents another obligation. Absence by itself never discharges an outstanding mutation. A bounded wait is an availability limit, not a fencing mechanism.

Do not expose a generic reset, SQL delete, namespace rotation or caller-provided `cleanup_confirmed` boolean. Operator recovery requires explicit evidence resolving the same obligations, preserving their history. Settled-history pruning must retain the identity/replay guarantees this protocol needs and cannot discard unresolved entries.

## Required acceptance before enabling release

- Two actual scanner jobs complete sequentially through the packaged controller/authorizer/TLS engine path, with independent reconciliation between them.
- Pause before and after mutation admission and before the native response callback; finish, cancel, expire, revoke, restart or lose the acknowledgement at each boundary. Unknown mutation state keeps admission held.
- Race closing admission with create/start admission and race stale reconciliation with a new obligation. Exactly one transactional ordering wins; no later operation executes under a released generation.
- Wrong worker, observer, authorizer, owner, engine, registry, launch, descriptor, generation or completion identity cannot admit, settle or release another job.
- Observer loss, engine replacement, unexpected named allocation, extra/missing launch membership, changed files and uncertain deletion preserve quarantine.
- Test acknowledgement replay, process crashes, restore/revocation, migration checksum preservation and failed local journal writes. No mutation retry or fallback engine listener is introduced.

Public acceptance output contains test names and statuses only. Credentials, runtime allocation records, journals, source paths and TLS material remain private. Full v4 and public beta remain NO-GO until their other gates also pass.
