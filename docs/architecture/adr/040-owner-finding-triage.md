# ADR 040: Owner finding triage beside immutable evidence

Status: implemented and locally verified; full v4 release remains unfinished.

## Decision

Store owner review decisions separately from immutable scanner receipts/results. A decision is bound to the owned job, immutable result digest and normalized record ID. It never changes source finding severity, confidence, provenance, suspected status or T0 tier, authorizes execution, marks a fix verified, or releases scanner admission.

Provide an explicit review disposition: suspected (reopened), unverified, false_positive or accepted_risk. Each noninitial decision requires a bounded local operator rationale. The rationale is escaped in the console, excluded from ordinary audit data and never automatically sent to AI. A false-positive or risk decision is an operator assessment rather than scanner proof. Other evidence-backed workflow transitions require separate verification work and are not exposed by this operation.

GET/POST `/api/v1/scans/{id}/finding-triage` establish owner scope and revalidate the immutable result/receipts before selecting the exact normalized finding. GET uses an exact record_id query; POST uses strict typed JSON, CSRF/origin enforcement, an idempotency key and an expected revision. An exact retry returns its original immutable decision; a changed retry or stale revision conflicts. An owner cannot attach a disposition to another job/result/finding.

Append-only decisions and audit records commit atomically. Per-record revision and global row/byte budgets bound history; no historical decision is overwritten or silently removed. Missing/corrupt evidence remains unavailable rather than becoming an empty/clean finding. Initial read-only state has revision zero and no operator rationale. Triage never suppresses source claims or changes finding counts.

## Required validation

Challenge owner/result/record isolation, stale/concurrent writes, exact/lost-response replay, append-only triggers, rationale/row/byte budgets, migration preservation, atomic audit rollback, corrupt source and triage records, cancellation and restart persistence. Exercise real parsed fixture findings through the public HTTP boundary, generated clients and browser review controls. Keep source receipts and cleanup holds unchanged.

Cross-job catalogue/history, evidence-backed promotion, investigations, remediation and the remaining v4 release gates continue beyond this increment.
