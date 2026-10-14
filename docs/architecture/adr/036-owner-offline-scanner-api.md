# ADR 036: Owner offline scanner API

Status: implemented for provisioned offline repositories; result UI, independent cleanup verification and background worker deployment remain unfinished.

## Decision

Expose the existing durable scanner queue through the owner session API at `/api/v1/scans`. The deployed API prefix follows the existing local service convention; the operations implement v4 F2's `/v1/scans` intent. POST requires CSRF, an idempotency key, the owned repository's current map, sorted unique supported tool IDs and a 1–120 second tool budget. Owner, image, command, filesystem path, worker capability and cleanup assertions cannot be supplied in the request. Only `app_demo` and provisioned read-only offline repositories are currently supported. The controller and private channel share the same startup-provisioned queue and pin/guard configuration; without scanner provisioning these operations return 503.

GET `/scans` returns at most the latest 100 owned jobs. GET `/scans/{id}` returns the job plus execution admission. POST `/scans/{id}/cancel` accepts an empty object and returns that status; repeat cancellation is idempotent. GET `/scans/{id}/result` revalidates the immutable index and its normalized receipts and returns the original digest. An owned job without a result returns 409 `RESULT_NOT_READY`; an unowned or missing job returns the same 404. Result objects keep T0 claim counts, independent stale/partial/error flags and `cleanup_required: true`.

## Admission and authority

Status reads the job and its dispatch in one database transaction. `not_claimed` applies to queued jobs and queue-expired jobs with no dispatch. An active dispatch reports `active`; a terminal dispatch awaiting independent verification reports `cleanup_required`. A cancelled job with no dispatch reports `unconfirmed`, without claiming resource absence. A missing dispatch for an executed terminal result is a conflict, not evidence of cleanup. No owner operation renews a worker lease, finalizes a scanner result, removes a dispatch or grants Docker access.

All routes use existing owner sessions, mutation serialization, strict bounded request decoding, CSRF/origin enforcement and no-store response headers. Cross-owner reads, cancellation and repository selection are refused. The public response contains neither lease capabilities nor worker credential material. Workspace/launch journals remain on the private channel.

## Contracts and evidence

Generate ScannerJobInputV1, ScannerJobV1, ScannerJobListV1 and ScannerJobStatusV1 alongside OpenAPI and Go/Python/TypeScript clients. Standalone client response limits are 128 KiB so the declared bounded 100-job list remains readable. Requests retain the existing 64 KiB strict bound. Owner HTTP tests cover auth, cross-origin/CSRF, hostile/unknown fields, idempotency, owner isolation, cancellation and admission retention. Component interoperability tests read real six-adapter normalized result data through the public handler; explicit native fixtures also check results after actual pinned scanner execution. The deployed generated-client acceptance queues and cancels a job without executing repository code and runs in trusted-demo CI.

These checks are local component/demo evidence, not independent installation or security certification. The original preflight tool-error attempt remains recorded separately from successful follow-up execution; tests never reclassify it as a clean scan. See `docs/evidence/scanner-owner-api-acceptance.json` and `scanner-owner-api-live-acceptance.json`.

## Remaining v4 work

Owner findings detail and result UI, independent cleanup verification/release, deployable worker/socket pairing, background execution, offline database freshness, disposable VM arbitrary-code execution, AI/MCP/desktop integrations, signatures, supply-chain/legal review and independent H7 release gates remain required. The bounded list is not a full paginated findings API. This increment does not make held admission reusable or claim production-ready scanning.
