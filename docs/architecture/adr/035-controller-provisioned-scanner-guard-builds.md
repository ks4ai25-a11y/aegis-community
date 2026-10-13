# ADR 035: Controller-provisioned scanner guard builds

Status: implemented for the fixed private worker protocol; independent cleanup verification and release remain unfinished.

## Decision

The controller image builds and packages both Linux guard architectures using the pinned Go 1.27.1 toolchain, CGO disabled, trimmed paths and VCS metadata disabled. Native research builds use the same guard flags. Startup reads only the fixed names in a canonical operator-provisioned guard directory, refuses symlinks/nonregular files and applies a 32 MiB per-build bound. It checks ELF architecture and Go command/toolchain/build settings, then computes the actual two file hashes and a canonical guard-set digest. It never executes these artifacts or accesses Docker.

This establishes locally provisioned package identity, not publisher signatures or runtime attestation. A host administrator can replace packages or forge build metadata; signatures and independent supply-chain review remain required.

## Authority and evidence

Additive migration 11 stores `scanner_dispatch.guard_set_digest`, defaulting to empty for historical dispatches. A fresh claim requires a valid provisioned two-architecture set, binds that digest to the original dispatch and audit, and returns the bounded set only on the private enrolled-worker channel. Renewal, capture reservation and new launch authorization refuse an empty or changed guard-set binding. Rotation does not extend or revive original authority; uncertain admission remains held.

Launch document schema 1.1 adds guard-set/protocol metadata and a plan naming the prepared guard digest and architecture. The controller accepts only a member of its current dispatch-bound set. The worker checks its prepared guard bytes against the acknowledged set and validates the complete launch acknowledgement before sending Docker the fixed command. New executed receipts must match the approved launch guard digest. Controller-derived original deadline and the approved guard's absolute-deadline ABI remain fixed.

Historical schema 1.0 launch documents remain owner-readable and hash-checked with omitted guard fields; migration never rewrites them or invents guard authority. Exact committed receipt/result replay preserves evidence without permitting execution. V1 generated launch contracts remain historical; `ScannerGuardSetV1` and V2 launch contracts describe the new binding.

## Remaining cleanup boundary

A matching launch/receipt digest is still worker evidence, not proof that Docker mounted or ran those bytes. Independent verification must inspect the trusted original engine, actual guard/source mounts, queued-request/late-start state and provisioned registry, exclude active leases, account for incomplete allocation and authorize cleanup release separately. No guard binding, reservation, receipt or result releases admission. Old guard-less records cannot acquire cleanup proof through upgrade.

Native fixtures use operator UID; deployable pairing with Compose UID 10001, a background scanner service, arbitrary-code disposable VM isolation, full result UI/findings, offline databases and independent H7 release gates remain unfinished.

## Verification

Tests reject altered guard sets/protocols, missing provisioned sets, worker-selected guard hashes/architectures, rotated or legacy dispatch bindings and receipts with a different guard. Loader tests refuse unprovisioned, symlink, wrong-architecture, fake-build and oversized artifacts. Migration tests preserve prior state/checksums without invented authority. Real pinned scanner fixtures load actual packaged-compatible guard builds and bind their launch/receipt metadata. Native and Docker guard hashes must agree before rollout. See `docs/evidence/scanner-guard-binding-acceptance.json`.
