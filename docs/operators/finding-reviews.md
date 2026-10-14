# Reviewing scanner findings

Open an owned terminal scan in Scans. Static finding details retain the scanner claim, source versions, severity disagreements, receipt identities and T0 classification. The separate Owner assessment summary shows the latest local review decision. Open Review triage to read the exact current revision before recording a decision.

Available review dispositions are unverified, false positive, accepted risk and reopen as suspected. These are owner assessments. They do not verify exploitability, establish a fix, suppress source claims, change severity or confidence, approve a policy or release scanner execution admission. Evidence-backed corroboration, reproduction and remediation transitions need their own verification workflows.

Each decision requires a local rationale of 5–512 UTF-8 bytes without control characters. Keep credentials and private source text out of it. The rationale is stored in the owner-scoped local controller database and rendered as text; it is not copied into ordinary audit events or automatically sent to a model. The audit instead records the decision digest, state, revision and bound result/finding identities.

An unchanged retry after a lost response reuses its idempotency key and returns the original decision. Another edit may have advanced the current revision; reload the current review before making a new decision. A changed retry or stale expected revision conflicts rather than overwriting someone else's work. Reloading replaces unsaved form edits with the recorded decision.

## HTTP contract

- GET `/api/v1/scans/{job_id}/finding-triage?record_id={exact_record_digest}` reads the owner-bound decision. Revision zero explicitly means no owner decision has been recorded.
- POST the same path with `FindingTriageInputV1`, owner session, CSRF token and `Idempotency-Key`. Bind the exact immutable result digest, finding record ID and expected revision. Browser-selected owner identities, execution commands and proof-tier transitions are unsupported.
- `FindingTriageRecordV1` includes the document digest and previous decision digest. GET finding pages also include optional owner_review records; the current controller emits them for every selected record. Clients validate identity and digests before displaying assessments.

Every read/write revalidates the owned immutable scanner result and source receipts. Missing results are unavailable, not clean. Another owner's job/finding remains unavailable. Invalid or stale evidence/review history is refused. Stored decisions and their audit append commit together.

History is append-only: at most 50 decisions per job/finding, 20,000 decisions and 16 MiB of decision documents globally. Capacity exhaustion refuses new writes; it does not silently discard prior reviews. Cross-job review carry-forward, a global catalogue, history browsing/export and user-configurable retention remain unfinished.

## Schema 12 upgrade

Back up the controller database with the existing private local backup procedure before upgrading. Migration 12 adds only the finding-triage ledger and immutable-history triggers; versions 1–11 retain their original checksums. Initialize with the new shared controller image, then align the named init, controller, deployer and verifier services with that image. Follow the existing local-demo upgrade guide. Re-run doctor, local audit verification, source/API/browser checks and the trusted demo journeys. A successful local upgrade is not independent release certification.
