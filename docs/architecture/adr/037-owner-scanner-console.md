# ADR 037: Owner scanner console

Status: initial offline request/status/suite UI implemented; individual findings, independent cleanup verification and background worker deployment remain unfinished.

## Decision

Add a Scans page to the existing local console using the generated owner scanner API. Owners choose a connected provisioned repository, inspect its map identity, choose fixed tools, set a whole-number 1–120 second per-tool budget and authorize read-only use of that snapshot. Requested tool IDs are sorted. Browser inputs cannot select paths, images, commands, worker roles or arbitrary targets. Offline advisory database prerequisites are shown for OSV and Trivy; a queued request is not evidence that a worker is available or a scanner ran.

After an uncertain submission acknowledgement, an unchanged request retains its idempotency key for retry. Changing the request creates a new identity. A successful acknowledgement clears that retry and consent state. Error text remains visible in the scanner component, even if the global gateway status refresh succeeds. Consent resets when tools, repository or duration change.

## Status and evidence

The page lists the latest 100 owned jobs, inspects status/admission, polls selected queued/running jobs every two seconds without overlapping requests, and supports cooperative cancellation. Request-generation checks exclude stale reads from previously selected jobs and unmounted views. Result fetching completes before switching the poll to terminal state, avoiding loss of evidence when the polling effect stops. Direct and polled results must match job/request/owner/repository/map/tool-lock identity and terminal status, retain T0 classification and retain the cleanup requirement. A mismatched result is cleared and refused, not rendered.

Suite views preserve independent partial, stale-database and tool-error flags, per-tool status, SBOM presence, receipt references and the result/snapshot identity. Claim totals are explicitly tool claims, not cross-tool deduplicated vulnerabilities or proven exploits. Failed, cancelled, timed-out or missing-result jobs never become fabricated zero-findings results. Admission/cancellation displays distinguish not claimed, active, cleanup held and unconfirmed resource state; no UI action releases admission.

## Browser verification

Pinned Playwright 1.64.0 tests the built console with isolated synthetic API contract fixtures. Challenges cover read-only consent, budget validation, lost acknowledgement/exact retry, cancellation, terminal tool-error polling, delayed prior-job responses, direct and polled identity mismatches, and 390-pixel mobile layout. Fixture screenshots are labeled by the evidence report; they are not actual scanner execution claims. CI installs the pinned test browser and runs these checks separately from the module/build suite.

An explicitly enabled live check uses only the named loopback demo. It logs in with the protected local test credential, queues/cancels a real safe-repository request and signs out. It never executes repository code, uses a user browser profile or contacts an AI provider. Tracing is disabled for this test so real owner credentials/session material cannot enter trace artifacts. Native worker/parser and API acceptance remain separate evidence for scanner execution/result integrity.

The first fixture run used a completed suite where an error suite was intended; it was corrected rather than changing the expected error semantics. The mobile challenge then caught an unwrapped source digest causing horizontal page overflow; the request card now wraps that digest. Failure logs/traces are retained separately from passing final evidence. See `docs/evidence/scanner-console-acceptance.json`.

## Remaining scope

This is initial scanner request/status/suite presentation, not the full findings detail/deduplication workflow. Independent engine/workspace cleanup verification and release, deployed worker/socket pairing, background service operation, offline databases/freshness, disposable VM arbitrary-code execution, AI/MCP/desktop integrations, supply-chain/legal/security review and all independent H7 release gates remain required. Public beta remains NO-GO.
