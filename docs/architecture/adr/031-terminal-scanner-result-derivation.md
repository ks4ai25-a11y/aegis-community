# ADR 031: Terminal scanner results from immutable receipts

Status: implemented; independent cleanup release and release gates remain open.

## Decision

The private worker channel adds `POST /internal/v1/scanner/finish` with only `job_id`, `request_digest` and `lease_token`. It accepts no requested status, findings, result document or cleanup confirmation. The controller derives a result from exactly one accepted receipt for every requested scanner, in canonical tool order. Missing receipts are a conflict, never empty coverage.

Before a new result, the controller checks current enrollment, original lease capability, live deadline, cancellation, repository map and startup lock identity. It verifies each stored receipt's content/relational identity and normalization against the historical approved map and originally accepted tool identity. All receipts must bind the same snapshot. The result indexes receipt digests and finite per-tool statuses rather than duplicating raw output, source or SBOM contents.

Overall status uses conservative precedence: `tool_error`, then `completed_partial`, then `completed_stale_db`, then `completed`. Independent partial, stale and error flags are preserved, including mixed cases. `finding_claims` sums per-tool claims; it is not a cross-tool deduplicated vulnerability count. All evidence remains T0. A completed static scan provides no clean application, exploitability or remediation proof.

Additive migration 8 stores one immutable result per job. Result insertion, job terminal state/time, dispatch transition to `cleanup_required`, and the terminal audit event commit together. Results have a 16 KiB bound and 1,000-row budget; archive rotation remains unfinished. Previously deployed migrations are unchanged. Owner-scoped `Queue.Result` verifies the index against its receipts; public scanner result routes and UI remain required.

Exact replay checks original worker/capability, owner/request identity and active enrollment. It reads the committed result, even after lease expiry or pin rotation, without execution authority, another audit event or admission release. Conflicting/tampered stored data is refused. Receipt/result immutability is enforced within the application/local-host trust boundary, not against an administrator capable of changing SQLite and hashes.

## Worker behavior

The one-shot worker collects all requested structured receipts, including tool errors when local cleanup is safe. Capture, authority, receipt or uncertain cleanup failures still halt execution. After its lease keeper joins and performs the final guard, it requests finish. The client checks the exact document digest, original job/map/lock/snapshot identity, accepted receipt references, terminal timestamp and derived status/flags/counts. A finish-channel failure reports `finalization_unconfirmed` rather than claiming a terminal result.

CLI output now contains the durable result and its terminal scan status. A `tool_error` result exits nonzero. Successful complete/partial/stale results exit zero with their exact status; none asserts independent cleanup. This supersedes ADR 030's temporary `awaiting_controller_finalization` behavior.

## Unfinished boundary

Finalization leaves global admission occupied as `cleanup_required`. A worker's cleanup field cannot free it. Independent container/workspace confirmation, a trusted cleanup-verifier deployment, automatic recovery, background worker pairing and a reusable scanner service remain required. Native operator-UID component acceptance does not establish access to Compose UID 10001's socket. Arbitrary repository code requires disposable VM/host isolation, which remains absent.

## Verification

Tests cover complete/partial/error derivation, mixed stale flags, incomplete requested suites, original capability/owner/request binding, expiry/revocation/cancellation/map/lock refusals, atomic audit rollback, immutable restart replay, cross-owner reads and tampered result/receipt detection. The actual six parser fixtures aggregate through the private channel with retained stale-database uncertainty. Real pinned Bandit with a seeded eval finding, Bandit/Gitleaks and Bandit/OSV/Trivy fixtures exercise the one-shot path, terminal results and retained cleanup admission. Actual result payloads match generated Draft 2020-12 schemas. These are bounded fixture claims, not full H7 acceptance.
