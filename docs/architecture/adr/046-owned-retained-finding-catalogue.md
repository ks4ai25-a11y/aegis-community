# ADR 046: Owner-scoped retained finding observations

Status: implemented and locally validated; full v4/H7 acceptance remains incomplete.

## Decision

Add an authenticated read-only `GET /api/v1/findings/catalogue` and a Findings navigation page. Browse all retained result identities for the owner, independent of the latest-100 scan-job screen. Support owned repository, category, claimed severity, result-time range and page-size filters. Each response projects at most twenty records from one exact immutable scan result through the existing evidence/triage validator and includes that result's suite, coverage flags and receipt-linked findings. Share the existing finding renderer, review controls and history/export path.

Do not total repeated scan observations into a vulnerability counter. Equivalent source claims within a scan retain the existing conservative deduplication; different scans/snapshots remain explicit observations. A result with no matching records retains its coverage/error state and cannot establish a clean repository. Jobs with no immutable result have a separate count across all times in the selected repository scope. Neither missing execution nor a failed tool becomes zero findings.

Read the owner-bound result roster and selected source evidence in one database transaction. The existing global queue budget limits metadata to one thousand jobs; reject excess rows. Check result-owner/request bindings before including result identities. Parse timestamps and sort by actual instant plus job ID, including whole-second versus fractional-second values. `since` is inclusive and `until` exclusive; normalize offset timestamps to UTC before binding query identity. Reject invalid/reversed ranges. Only the selected result's source evidence is fully revalidated on that page; the retained-result count describes stored result identities, not verified vulnerabilities or whole-corpus coverage.

Bind the canonical cursor to owner, normalized filters/page size, ordered retained result identities and timestamps, result position and the inner finding cursor. Re-read ownership and evidence on every page. A changed retained-result set returns `CATALOGUE_CHANGED` and requires restart rather than mixing histories. New jobs without results do not change the immutable roster; their separately reported count is current at each read. Review heads may advance without rewriting the immutable result set. No cursor grants authority and no mutable global index or migration is introduced.

## Bounds and UI

Keep a five-second request context and 120 KiB complete response limit inside the clients' 128 KiB limit. Reuse the result returned by the finding projection rather than validating/decoding the same receipts a third time. A result exceeding source/provenance/page bounds returns a resource error; it is never skipped or hidden behind an empty success. One scan's finding pages finish before the next retained scan. A zero-match scan still occupies a page with explicit coverage and continuation.

The console obtains the authenticated owner identity, rejects mismatched result/page/finding/review scope, preserves T0 classification and coverage/error flags, and invalidates obsolete reads when filters change. Result-set and position continuity must match the previous page. Filters reset pagination. A source link opens the exact selected scan through the existing Scans inspector. Rationales and source metadata remain text; no model upload, scanner execution, review carry-forward or admission release occurs through catalogue reads.

## Validation and remaining work

Challenge all finding pages, terminal errors, missing results, metadata/source corruption, other-owner repositories/cursors, changed result sets, invalid query coordinates, cancellation, historical results beyond one hundred newer jobs, timestamp boundaries and nanosecond ordering. Exercise actual parser evidence through authenticated HTTP and generated clients, and browser navigation/filter/continuation/mismatch/late-response/mobile checks. Record observed results separately.

This increment provides retained observations, not a completed cross-revision canonical finding graph, globally deduplicated vulnerability total, source-code fix/proof lifecycle or independent release acceptance. Larger retention/indexing and arbitrary application registrations remain future work. The scanner cleanup gate remains held and all other unfinished v4/H7 work remains active.


## Observed evidence

`docs/evidence/finding-catalogue-acceptance.json` records 33 focused race test events across three repetitions, six additional repeated cross-owner/time-offset checks, actual parser/HTTP catalogue payloads, five schema validations/eight refused variants, 51 console browser passes (two opt-in skips), six packaged API checks and one deployed read-only owner browser pass. The native channel suite passes 21 tests with four opt-in engine skips. Full `make test` and final controller API race/vet checks pass. Readable desktop/mobile screenshots were inspected. The four named image-sharing demo services retain UID 10001, read-only roots, cap-drop ALL and controller socket/mount restrictions; readiness and gateway revision remain stable after the private pre-update snapshot. This does not complete any independent release gate.
