# ADR 057: Scanner mutation admission and confirmed cleanup release

Status: partially implemented. Migrations 014/016 implement authorizer enrollment and the controller mutation ledger. Packaged native admission and the bounded independent TLS reader have passed hosted acceptance. Migration017 adds separately scoped reconciler enrollment and complete closed-generation metadata. Independent reconciliation and release remain unfinished. Scanner admission remains held after a dispatched job.

## Problem

The permanent `cleanup_required` hold prevents repeated scanning. Removing it after a worker reports success, a local journal settles or an observer sees no container would permit a previously admitted create/start to complete after release. ADR 053/054 observations are read-only snapshots, and ADR 055 packages those preconditions; none supplies durable mutation admission or cancellation fencing.

## Decision

Release needs a controller-owned mutation ledger, a distinct authorizer capability and independent engine reconciliation. Keep worker, broker, authorizer and observer roles separate. Existing `scanner-verifier` enrollment remains read-only; extending its permission would silently change a deployed capability. A new narrowly scoped authorizer enrollment must bind owner, engine, registry and serving policy, expire and revoke monotonically, and be separately provisioned. Never accept worker credentials on this channel.

Migration 014 adds retained immutable authorizer enrollments, with no automatic enrollment or mutation permission. Backup/recovery validation, identity contracts, version-13/14 compatibility and restore revocation advance together. All earlier migration bodies and checksums remain unchanged. The allocation ledger needs a separately coordinated migration; restoration must preserve unresolved mutations and cleanup holds.

The implemented operator surface is described in [scanner authorizer enrollment](../../operators/scanner-authorizers.md). Identity probing proves enrollment only; selected native serving additionally uses the private scoped launch/admission/completion operations. Existing observer capabilities remain read-only; no current serving command interprets authorizer enrollment as permission to allocate. The remaining protocol below is the implementation contract, not a claim that fencing or release has shipped.

### Implemented workspace prerequisite

Fresh-only native registry initialization now creates a private protocol-2.0 namespace bound to its original canonical path, UID and filesystem device/inode, with a fresh nonce. Existing registries cannot be promoted in place. The approved namespace digest is required by the new bound empty-registry callback API; read-only-opened kernel locking spans the entire synchronous callback. Unknown or replaced state is preserved and refused. New Close operations hold the same global creation lock, positively close the lifecycle lease before deleting the original workspace through a confined handle, and sync before success. A failed or uncertain close cannot turn an occupied workspace into a successful empty-registry observation.

This is one reconciliation prerequisite, not controller release authority. Legacy registries and peers do not gain attestation from an empty directory. Mutation fencing, a distinct reconciliation capability, exact engine observations and atomic controller release remain required. See [workspace barriers](../../operators/workspace-registry-barriers.md).

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

### Migration 016 implementation increment

The controller ledger now retains selected authorizer/namespace bindings, random per-dispatch generations, immutable create/start/remove intents and successful native-response confirmations. Selection is local-operator-only, requires the existing engine/journal/broker binding and live authorizer, refuses adopting any outstanding dispatch, and cannot replace active selection. A revoked selection cannot silently downgrade a later claim to the legacy path. Legacy claims receive no generation or release authority.

Admission rechecks original dispatch identity, deadline, worker/broker, registered launch/workspace, guard and selected authorizer scope in the transaction that persists the intent. Starts require a confirmed create identity; tracked removal can be admitted after job closure, with no unresolved earlier mutations. Exact admission replay returns the original record with an explicit replay flag and must never cause another daemon operation. Completion records only successful native responses (create 201, start/remove 204); unsuccessful, missing or uncertain responses remain pending. Response replay is immutable. Completion does not prove independent absence.

Database triggers close generations on cancellation, terminal job/dispatch transitions, worker/authorizer revocation and selected-binding revocation; obligations remain retained. Worker workspace/launch registration refuses a closed generation, and the old observer-only live-launch serving path refuses generation-enabled jobs. The dispatch remains held even after all responses are recorded. Migration 016 restore revokes selected bindings and closes generations while preserving every intent and cleanup hold; supported older schema prefixes remain unchanged during offline restore.

The native `serve-admitted` mode and local `scanner-authorizer bind` selection now use these operations. Local real-Unix controller/plugin-policy tests cover admission-before-Allow, durable-response-before-completion, cancellation, uncertain admission and a lost committed response acknowledgement. Packaged native-daemon admission and bounded original-scope ID/name observation have passed hosted CI. Independent reconciliation/release, actual mediation proof, sealed crash repair and two actual sequential packaged scans remain required before repeated-scan support is claimed. See [native mutation admission](../../operators/native-mutation-admission.md).

The separate admitted Compose profile and guarded GitHub Linux AMD64 acceptance now exercise the intended actual-daemon path. Its verifier requires the selected namespace/policy, exactly matching native/controller create-start-remove records, closed generation and held second job, with private snapshot/journal data kept out of logs/artifacts. Synthetic verifier tests reject missing/pending/changed/open state and unsafe evidence destinations. Hosted execution of this new path is pending; none of these additions enables independent release.

Migration017 reserves independent cleanup confirmation for a separate binding-scoped reconciler, without elevating older observer credentials. Its current private context protocol enumerates all retained reservations, launches and mutation obligations in one read transaction; no caller-selected subset or release/reset operation exists. Snapshot membership changes with obligations and completions, while freshness is separately challenge-bound. Restore revokes the new capability and retains all original holds. See [reconciler operations](../../operators/scanner-reconcilers.md). This is metadata infrastructure, not evidence that native all-write mediation or release has been verified.
