# ADR 038: Owner static finding projections

Status: implemented for immutable owned scan results; global cross-job catalogue, triage mutations and proof promotion remain unfinished.

## Decision

Expose `GET /api/v1/findings` with required owned `job_id` and optional category, claimed severity, limit and cursor filters. Requests without a selected job are refused rather than scanning all retained source state. This is the initial job-filtered part of v4 F2's finding API; a global cross-job catalogue remains required. OpenAPI generates the query parameters and Go/Python/TypeScript methods from FindingQueryV1; filters travel in the URL, not a GET body.

Reads run in a five-second context and one database transaction. The immutable result and all original normalized receipts are revalidated against historical map/pin/time/owner identities before projection. Reads do not mutate receipt/result evidence, audit state, worker leases, proof tier or cleanup admission. A missing owned result returns 409; an unowned/missing job returns the same 404. Invalid/unknown/repeated filters and unbound cursors are refused. Corrupt evidence cannot become an empty result.

## Deduplication and identity

Move the existing static aggregation algorithm into the shared executor-free evidence package. The standalone alpha adapter retains its 10,000-input bound; six-tool controller aggregation permits at most 60,000 tool claims under the existing receipt ledger's byte cap. Exact PURL/version/advisory/lockfile/input identities can aggregate dependency sources. Claimed severity takes the highest supplied claim, while each original source's severity remains visible. T0, suspected state and low confidence never become reproduced proof.

Different snapshots/repositories/owners remain separate. No advisory alias/range equivalence or cross-tool AST equivalence is guessed. Without a PURL, dependency tool namespaces stay separate. Projection `record_id` includes owner/input/source namespace so equal incomplete parser IDs cannot collapse distinct presentation records; the underlying finding ID remains available. Source records and original receipt digests are retained, and a provenance overflow is an explicit resource error rather than truncation. Static line/rule keys remain conservative source observations; richer AST/region context and cross-job triage history remain required by the full v4 design.

## Pagination and resource bounds

Pages contain at most 20 records and stay below 96 KiB, inside the standalone clients' 128 KiB response bound. A byte-limited page advances without dropping records or source provenance. Counts distinguish original tool claims, distinct static records and records matching current filters; none is a confirmed-vulnerability count. Empty filtered pages retain the result's partial/stale/tool-error flags.

The cursor is a canonical base64url seek coordinate containing result digest, filter/owner/job/page-definition digest and offset. It is not an authorization token or a signed capability. Every read independently enforces owner authority and immutable result context. Changed result/filter/page definitions, malformed/noncanonical cursors and invalid offsets are refused. The original immutable view survives restarts without a new signing secret or invented authority.

## Console

The selected immutable scan now opens normalized finding details with category/severity filters and bounded pagination. It shows path/line, declared package/advisory, suspected/T0/low-confidence state, tool/version/parser, each severity claim, input/image identity and receipt references. It never displays matched credential values or raw scanner messages. React text rendering escapes hostile presentation content. Response-generation checks exclude delayed filter reads; result/input/owner/source/receipt bindings are checked before rendering, and mismatched pages clear prior records instead of implying empty/clean output.

## Evidence and remaining scope

Controller tests cover pagination, byte bounds with 16-source records, missing/corrupt results, context cancellation and cursor/owner/filter isolation. A six-adapter fixture deliberately aligns OSV/Trivy package/advisory claims: five tool claims produce four static records, retaining both original dependency sources and severity disagreement. Separate native fixtures execute actual pinned scanners and read their findings through the public handler, including honest missing-database tool errors. Browser tests cover pagination/filtering, delayed responses, mismatched pages, hostile HTML and mobile layout. Named local demo acceptance checks pending-result findings remain unavailable, never zero claims.

These are component/local-demo checks, not independent installation, execution attestation or security sign-off. Global catalogue/triage persistence, AST-aware equivalence, independent reproduction/remediation, cleanup verification/release, deployed worker pairing/background execution, offline databases, disposable VM execution, AI/MCP/desktop integrations, signatures/supply-chain/legal review and independent H7 release gates remain unfinished. See `docs/evidence/finding-projection-acceptance.json`.
