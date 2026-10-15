# ADR 048: Operator-bound scanner engine and workspace registry

Status: implemented experimental operator scope binding. Independent engine mediation and cleanup release remain unavailable.

## Problem and decision

An enrolled worker previously chose the first launch's engine and workspace-registry identities. Later launches had to match, but that did not establish prior operator approval of the initial host scope. Add a separate immutable controller-local provisioning record for the existing repository-mount owner, engine digest and workspace-registry digest. This is an operator setting in schema 13; no migration or browser provisioning endpoint is introduced.

`aegisctl scanner-engine bind ENGINE_DIGEST REGISTRY_DIGEST` requires an owned provisioned repository and no dispatch slot before the initial insert. It validates canonical bounded content and commits the record and audit together. Exact repeats return the original identity without another audit. Replacement, reset, cross-owner provisioning and provisioning over an active/held slot are refused. A corrupt setting is never interpreted as unconfigured legacy state.

The authenticated private worker channel exposes a finite read operation only. It rechecks live enrollment and owner scope in its database transaction. The client validates canonical wire content, owner, hashes, canonical UTC creation time and document digest. Browser sessions, observer credentials, payload-selected owners and mutation requests cannot provision the setting.

Every workspace reservation and launch checks a configured scope in the same transaction as its original authority and immutable record. The scope constrains legacy clients too. A changed registry cannot reserve source allocation; a changed engine cannot register launch. Existing legacy experiments remain possible in databases without provisioning; their absence of binding is not upgraded into an approval claim.

## Reference packaged worker

The opt-in Compose profile now selects `worker-once-bound`. It requires the provisioning record before claiming, compares the configured registry and directly probes Linux engine identity through the fixed read-only SDK path before obtaining a lease. Missing, corrupt, changed or unavailable scope leaves the job queued. It repeats the scope comparison at launch, before engine writes, in addition to controller enforcement. Both direct identity reads and pinned-image checks ignore ambient proxy/API-version overrides and have bounded complete responses. A valid scope does not require a Bandit image just to identify the engine.

`engine-binding-input CANONICAL_REGISTRY` runs under the intended non-root worker identity and endpoint and prints only an untrusted provisioning input: engine/registry hashes with controller-binding and cleanup-release flags false. It creates no registry, journal or claim. The operator reviews those hashes before the local controller bind command. Since current engine identity includes the selected endpoint and registry identity includes canonical path and UID, calculate the input inside the actual packaged profile with the actual mirrored workspace path. A native desktop proxy endpoint is not interchangeable.

Restore revokes the prior host binding alongside worker/verifier authority, while retaining history and cleanup holds. A restored hold still cannot be cleared or bypassed to rebind a different host.

## Validation and limits

Focused race tests cover immutable/repeated/restarted binding, concurrent conflicting provisioning, absent owned source, active dispatch, transaction/audit failure, malformed/noncanonical/unknown/duplicate/digest/owner/future records, private read refusal and worker revocation. Worker/client tests exercise scope refusal before claim or allocation, actual read-only identity request ordering and malicious responses. Recovery tests prove old host authority is removed without releasing the slot. The isolated packaged harness checks missing provisioning, exact replay, changed provisioning and registry, then executes the actual guarded fixture and verifies the next job remains held.

This binds operator-approved metadata; it does not attest the host, bind a journal namespace, mediate all daemon clients, authenticate completed cleanup, exclude active leases/incomplete allocations/late starts, or provide a release endpoint. The trusted orchestrator still has engine authority. Journal/gate binding, an independent all-write broker and verifier/reconciliation remain required. Arbitrary source/patch execution still requires the v4 disposable VM boundary. Full release and independent review remain NO-GO.

## Observed local evidence

`docs/evidence/engine-binding-acceptance.json` records 66 repeated controller and 84 worker/client race test events, full source tests, controller/alpha vet, two actual schema-valid payloads and five refusal variants. `docs/evidence/engine-bound-worker-acceptance.json` records ten actual packaged checks, all six pinned tools, missing/changed provisioning refusal before claim, six committed receipts, retained T0 findings, settled non-authoritative journal, held second job and verified removal of the fixture's own resources. Missing advisory databases remain tool errors. The new shared contract changes the deterministic guard build identities; actual worker/controller packages agree on both builds without changing the guard protocol.
