# ADR 045: Complete owner review history and local JSON export

Status: implemented and locally validated; full v4 release acceptance remains open.

## Problem and decision

The append-only finding review ledger keeps earlier decisions, but owner reads and the console show only its latest record. Add an owner-session GET at `/api/v1/scans/{job}/finding-triage-history`, requiring the exact `record_id` and `result_digest`. Return the complete bounded decision chain under a canonical document digest. The document binds owner/job/finding/result, baseline and current head digests, revision count, completeness and ordered records. Revision zero has an empty decision array and the explicit synthetic baseline digest; it does not invent a decision.

Reuse the same ledger validator used by latest-review reads and writes. Within one database read transaction, revalidate the owned immutable scan result, source receipts, exact finding and every ledger row's canonical bytes, request binding, revision, predecessor and digest. Refuse missing/corrupt evidence, wrong owner, changed result, gaps or broken links. The existing fifty-decision bound permits a complete response under 120 KiB without silently truncating or introducing cursor ambiguity. Reads neither append decisions nor change audit/scanner evidence/admission. No schema migration is needed.

The console verifies scope, count, baseline, each record's digest and predecessor, current head and complete history digest before rendering or exporting. An older or conflicting head cannot replace an already displayed assessment. Changed scope/current assessment and component removal invalidate pending reads. Rationale stays escaped text. Export requires a deliberate button click and downloads the verified JSON locally, including rationales; no model/provider upload is involved. Histories remain owner assessments attached to one immutable scan and finding, with T0 tool claims preserved. They do not establish exploitability or remediation.

## Validation and limits

Observed: full `make test` and controller vet pass; 69 focused triage/history race test events across three repetitions, 21 private-channel/parser tests (four opt-in engine checks skipped), 31 browser checks (one live mutation journey skipped) and six read-only packaged checks pass. Two actual HTTP history payloads satisfy the schema and seven malformed/overstated variants are refused. Desktop/mobile screenshots were inspected. The four named image-sharing demo services are aligned, remain ready and serve the expected console bundle. Evidence is recorded in `docs/evidence/finding-history-acceptance.json`.

Tests cover complete and empty chains, all fifty decisions, unchanged source/admission, cancellation, ownership and exact-result isolation, corrupted receipt/ledger/request identities and broken predecessor links. Actual scanner parser receipts traverse the owner HTTP surface, including malformed/repeated/unknown filters, unsupported mutation, mismatched result and cross-owner rejection. Browser checks exercise actual Go payloads, exact downloaded bytes, desktop/mobile layout, escaped rationale, missing/reordered/corrupt/oversized history, stale heads and late responses after filtering.

Local hash chains are not publisher signatures or host-administrator tamper resistance. Complete means all retained decisions for the selected finding in the transaction's snapshot; refresh to see subsequent decisions. Cross-job review carry-forward, a global catalogue, evidence-backed finding lifecycle transitions, configurable retention and independent release acceptance remain unfinished.
