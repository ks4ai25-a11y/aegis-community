# ADR 033: Workspace reservations before source capture

Status: implemented for the fixed native static worker; independent cleanup verification and release remain unfinished.

## Decision

Add `POST /internal/v1/scanner/workspace` to the authenticated private Unix channel. A bounded plan names the selected tool, opaque random run ID, operator-provisioned registry digest and approved snapshot digest. No filesystem path, engine URL, command or cleanup boolean is accepted. The controller derives owner/job/request/app/repository/map/lock and original deadline from live trusted state.

Migration 10 creates an immutable owner/job/tool reservation ledger capped at 6,000 rows and 4 KiB per document. Reservation and `scanner.workspace` audit commit atomically. Workspace IDs are globally unique. One job cannot switch its reserved registry namespace. Owner-scoped reads verify hashes, relational identity and chronology. Exact reservation replay requires live enrollment, original lease, current source identity, pin lock and cancellation authority; an old acknowledgement cannot authorize allocation after expiry. Retention/archive rotation remains unfinished.

## Ordering and crashes

`workspace.BeginReserved` acquires the private registry lock, refuses occupied registries and generates the run ID. While retaining admission it calls the reservation callback before creating that run directory. The native worker submits the plan and checks every field of the controller acknowledgement against its local approved claim and original deadline. A channel/acknowledgement failure creates no run directory and copies no source bytes. The controller may already have committed; that reservation remains visible for later reconciliation.

After acknowledgement, the worker creates the private run directory/kernel lease and fsyncs a journal carrying the reservation digest before source capture. A crash during allocation or capture therefore has a previously recorded run ID. A later scanner launch must match that tool's workspace, registry and snapshot reservation and cannot predate it. Existing exact receipt/result replay remains immutable and grants no execution authority. Container-free preflight reports are still claims; they do not prove workspace absence.

The registry digest continues to identify the canonical provisioned namespace and effective UID under ADR 032. The controller never interprets that digest as an arbitrary path or independent ownership proof. A registry directory/lock can be provisioned before reservation; it is not a per-run source workspace.

## Compatibility and remaining verification

Claims now also require `workspace_protocol: "1.0"`. Fresh dispatches explicitly set the protocol. Existing dispatches retain their prior state, capability, launch records and admission with workspace protocol zero. They cannot renew or start new work through the updated live boundary. No migration fabricates reservations for historical captures. Upgrade initializer, deployer, verifier and controller together after a protected online backup.

This closes the supported worker's capture-before-launch identification gap. It does not attest that an allocation happened, a process stopped or a workspace was independently removed. An interrupted allocation may leave an incomplete journal; local recovery refuses malformed or unknown state, leaving admission held. Trusted namespace provisioning, independent original-engine/container/registry verification, late-start exclusion and a separately authorized cleanup-release mechanism remain required. Legacy/unsupported workers and host administrators are not proven absent by an empty reservation list. No admission is released by reservations, local recovery, receipts or finalization.

Native operator-UID fixtures do not prove worker pairing with Compose UID 10001. This does not supply disposable VM isolation for arbitrary code, a reusable deployed worker service, full finding/UI integration or completion of H7 release gates.

## Evidence

Race tests cover immutable replay, owner/authority/cancellation/revocation/legacy checks, changed plans and namespace reuse, tampering, late commit and audit rollback. Local workspace tests verify that the run does not exist inside the callback, concurrent allocation remains excluded and lost/invalid acknowledgements leave no run. Real client/controller fixtures simulate acknowledgement loss after commit and a captured orphan before launch; reservations survive expiry/reconciliation while admission remains held. Actual pinned scanner fixtures bind reservations to launch records and receipts/results. See `docs/evidence/scanner-workspace-acceptance.json`.
