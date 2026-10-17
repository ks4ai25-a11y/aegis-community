# ADR 070: Change-triggered rescans

Status: implemented (controller, API, console); no live stack run with a scanner worker yet.

## Problem

Scans ran only when an owner started one, so new code and new dependencies stayed unscanned until someone remembered (D9).

## Decision

`controller/internal/scanqueue/changes.go`:

- An owner opts a repository in with a fixed tool set and timeout. The policy is stored in the settings table (`rescan_policy/<owner>/<repository>`), so no schema migration is needed. Enabling records the current map digest as the baseline. At most 100 policies per owner.
- `CheckChanges` (aegisd, every minute, at most 10 policies, each no more often than `AEGIS_RESCAN_INTERVAL`) re-reads the repository through the registry's existing read-only `ConnectContext`. When the map digest differs from the baseline, it calls `Enqueue` with an idempotency key derived from repository, digest, tools and timeout, so one identity gives one job.
- It never claims, leases, releases or completes jobs and never touches dispatch slots. It defers while a job for that repository is queued or running, or while any of the owner's dispatches is `cleanup_required`.
- Outcomes are recorded on the policy and audited (`scanner.rescan_policy`, `scanner.rescan_triggered`).

## Consequences

Policies are part of the settings table, so they are captured in snapshots and recovery bundles. A restored installation keeps them, and they enqueue only through the restored owner's normal scan path. Map digests changed once when the Express, FastAPI and Flask route extractors were added (`e361ad4`), so every opted-in repository rescans once after that upgrade.

## Validation

Unit tests: no check without opt-in; another owner cannot set a policy; invalid tool sets refused; unchanged maps do nothing; a file change queues exactly one job with the policy's tools; the same digest is not scanned twice; a change while a job is queued defers; after cancellation the new identity is queued; the minimum interval is respected; disabling stops scans without cancelling queued work; a lost baseline after a crash reuses the same job; a held cleanup defers. An API test covers read, validation and update, and a browser test covers the console toggle.
