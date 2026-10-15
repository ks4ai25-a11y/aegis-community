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

History is append-only: at most 50 decisions per job/finding, 20,000 decisions and 16 MiB of decision documents globally. Capacity exhaustion refuses new writes; it does not silently discard prior reviews. Cross-job review carry-forward, a global catalogue and user-configurable retention remain unfinished.

## Schema 12 upgrade

Back up the controller database with the existing private local backup procedure before upgrading. Migration 12 adds only the finding-triage ledger and immutable-history triggers; versions 1–11 retain their original checksums. Initialize with the new shared controller image, then align the named init, controller, deployer and verifier services with that image. Follow the existing local-demo upgrade guide. Re-run doctor, local audit verification, source/API/browser checks and the trusted demo journeys. A successful local upgrade is not independent release certification.


## Browsing and exporting review history

Use **View review history** on an owned finding to load every recorded decision for that exact scan/result. The list shows ordered revisions, local rationales, timestamps and decision digests. No decisions means an empty chain, not a recorded approval. Reload to observe later decisions. History browsing does not discard unsaved review form edits.

Use **Export review history JSON** after a successful history read to download the complete verified chain locally. The export includes private review rationales: save it with the same care as other owner state. No remote upload or automatic model call is performed. The browser checks the complete chain and exact scope before enabling export; failures show unavailable history and never an empty/complete success.

GET `/api/v1/scans/{job_id}/finding-triage-history?record_id={digest}&result_digest={digest}` requires an authenticated owner session and rejects unknown, repeated or malformed filters. `FindingTriageHistoryV1` contains a canonical `history_digest` and a document with exact scope, `assessment_scope: owner_review_only`, baseline/head digests, revision count, `complete: true` and all ordered decision records. The response is bounded to fifty decisions and 120 KiB inside the clients' 128 KiB limit. It is a consistent read snapshot; later decisions do not rewrite a previously downloaded snapshot.

Owner assessments do not change the source finding's T0 evidence, approve policy or release scanner cleanup holds. Local hashes provide internal consistency under the existing host trust assumptions; they do not verify a publisher or prevent a host administrator replacing the whole history. See [ADR 045](../architecture/adr/045-finding-review-history-and-local-export.md) and [observed acceptance evidence](../evidence/finding-history-acceptance.json).
