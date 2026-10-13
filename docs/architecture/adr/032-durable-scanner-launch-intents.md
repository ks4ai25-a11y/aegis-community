# ADR 032: Durable scanner launch intents

Status: implemented for the fixed static worker; independent cleanup verification/release remains unfinished.

## Decision

Add `POST /internal/v1/scanner/launch` to the authenticated private Unix channel. An enrolled worker supplies its original job/request/lease binding and a bounded plan containing the selected tool, reserved Aegis container name, original engine digest, workspace ID, registry digest and approved snapshot digest. Paths, URLs, arbitrary commands and cleanup booleans are not accepted.

The controller checks live enrollment/lease/cancellation, current repository map and startup tool lock, selected tool and expected snapshot. It derives app/repository/owner, tool version/image, fixed profile, duration and original deadline from trusted state. Exactly one immutable attempt per job/tool is allowed. Container and workspace IDs are globally unique; a suite cannot switch its original engine or registry namespace. Authority is rechecked before new insertion.

Additive migration 9 stores the bounded document and its digest with an atomic `scanner.launch` audit event. The ledger is capped at 6,000 rows/4 KiB per document. It rejects update/delete under the controller/local-host trust boundary. Owner-scoped reads verify hashes and relational bindings. Archive rotation remains unfinished.

Exact launch replay requires a live lease even when already committed. Unlike receipt/result replay, a historic launch acknowledgement cannot authorize another start after expiry, terminal state, cancellation or revocation. A changed attempt is a conflict, never a retry with new container identity.

## Worker ordering

The fixed executor prepares its validated input/rules/guard, image, duration and random container name, then invokes the prelaunch callback before Docker receives the run command. The worker checks authority, fsyncs its local workspace/container/original-engine journal, submits the launch intent and validates the exact acknowledgement against its locally prepared pin, plan, job/map/lock and deadline. Channel or acknowledgement failure prevents Docker launch.

New executed receipts must match the registered container, snapshot, version/image, profile, lock and duration. A container-free preflight receipt cannot erase uncertainty from an existing registered attempt. An acknowledgement lost after commit may leave a launch without a receipt; admission remains closed. Existing immutable receipt/result replay preserves historical evidence without granting execution authority.

The registry identifier is `sha256` of `aegis-scanner-workspace-registry-v1`, newline, canonical provisioned registry path, newline, effective UID. The controller stores only the digest. This identifies a namespace for later verification; it does not authorize filesystem access or prove ownership independently.

## Compatibility and legacy quarantine

Claims advertise `launch_protocol: "1.0"`; the new native client requires it. Migration 9 adds `scanner_dispatch.launch_protocol` with default zero for existing dispatches. Fresh claims explicitly set one. Legacy dispatches retain original identity/state/capability and admission, but cannot renew/register new execution through the new live boundary. Migration creates no synthetic launch records and does not infer historical process absence. Upgrade initializer/deployer/verifier/controller together with the protected online backup procedure.

## Remaining cleanup boundary

A launch intent proves only that a proposed attempt was recorded before the supported worker sent its fixed Docker command. It does not prove that the process started, stopped or was independently cleaned. Docker/guard/cleanup fields remain worker claims. Global admission is never released by registration, receipts or finalization.

A crash during workspace allocation/source capture can precede the first launch intent. Zero launch records therefore cannot prove that a job has no surviving workspaces. Trusted namespace provisioning, earlier workspace/capture binding, independent original-engine/container/workspace verification, recovery and admission release remain required. Native operator-UID fixtures do not prove deployment access to Compose UID 10001. This does not provide arbitrary-code disposable VM isolation or a reusable deployed scanner service.

## Verification

Tests cover canonical envelope keys (including nested aliases/duplicates/nulls), bounded inputs, hidden general capability serialization, exact live replay, expiry/cancellation/revocation/legacy refusals, immutable attempts, original namespace consistency, unmatched executed/preflight receipts, audit rollback, claim protocol negotiation, and independently altered acknowledgements. Real pinned Bandit, Bandit/Gitleaks and Bandit/OSV/Trivy attempts are recorded and matched to receipts/results; seeded findings stay T0. Actual launch documents match generated Draft 2020-12 schemas. See `docs/evidence/scanner-launch-acceptance.json`.
