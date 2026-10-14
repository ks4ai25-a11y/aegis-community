# Contracts and generated research clients

Draft 2020-12 schemas currently cover demo policy, normalized source findings, exact provisioned repository records, application maps, source snapshot manifests, offline scanner execution receipts, fixed scope grants, scope approval, durable verification input/status, bounded verification reports and typed errors. `openapi-research.json` is OpenAPI 3.1 for the implemented repository/scope/job/report endpoints. It does not advertise unsupported v4 app/scanner/AI endpoints.

Generate bindings with `python3 scripts/generate_contracts.py`, then clients with `python3 scripts/generate_research_api.py`. Go, Python and TypeScript clients derive from the OpenAPI operations; the console Repositories and Verify pages uses the generated client. Go/Python admin clients restrict destinations to loopback, bound responses and refuse redirects. Supply an existing owner session and CSRF token; credentials are held in memory and never logged by these clients.

`tests/integration/contract_acceptance.py` checks actual local job, grant, report and finding payloads using pinned jsonschema 4.26.0 and tests malformed/overbroad examples. `samples/` contains sanitized synthetic runtime goldens, without owner session credentials. Generated client tests cover request shapes and destination/redirect restrictions.

Runtime typed decoding rejects unknown/duplicate fields. Additional semantic validators enforce ownership, expiry, total request budgets, immutable digests, policy constraints, leases and actual baseline/candidate evidence. Schema/type conformance alone does not grant authority or establish a security claim.

Still required: the complete v4 contract catalogue and API surface, runtime JSON Schema validation where appropriate, generated core/AI clients, version negotiation, compatibility tests and independent contract review. Aegis's invalid-domain schema identifiers are local identifiers, not remote services.

`SourceSnapshotManifestV1` and `ScannerExecutionV1` describe the operator-only execution boundary; no unsupported controller scan endpoint is advertised. `snapshot_scanner_acceptance.py` checks real pinned-image receipts against Draft 2020-12. Whole-source retention, durable scanner orchestration and independent provenance review remain incomplete.


`ScannerSuiteV1` and `ScannerSuiteResultV1` describe the immutable terminal index of accepted tool receipts. They preserve independent partial/stale/error flags and T0 evidence, require cleanup to remain pending, and count overlapping tool claims rather than deduplicated vulnerabilities. Actual native scanner fixture results are recorded in `samples/`. These schemas do not advertise a public scanner result route; semantic identity, receipt completeness and atomic derivation are enforced by the private controller boundary.


`ScannerLaunchPlanV1`, `ScannerLaunchV1` and `ScannerLaunchRecordV1` describe bounded private prelaunch metadata and immutable controller receipts. They accept opaque engine/registry digests and reserved IDs, without host paths or capabilities. They do not advertise a public launch operation, process-start proof or cleanup release. Exact launch replay still requires live worker authority; general launch-submission serialization omits the private capability.

`ScannerWorkspacePlanV1`, `ScannerWorkspaceV1` and `ScannerWorkspaceRecordV1` describe bounded private pre-capture reservation metadata. The plan contains opaque IDs/digests, never paths or cleanup authorization. These generated components do not advertise a public scanner workspace API. See ADR 033.

`ScannerGuardSetV1` and `ScannerLaunchPlanV2` / `ScannerLaunchV2` / `ScannerLaunchRecordV2` describe controller-provisioned two-architecture guard identity and schema 1.1 launch intents. V1 launch schemas remain for historical records without guard authority. These components do not advertise public launch routes, signatures or runtime/cleanup attestation. See ADR 035.

Owner offline scan operations now have ScannerJobInputV1, ScannerJobV1, ScannerJobListV1 and ScannerJobStatusV1 schemas and generated OpenAPI/client methods for enqueue, bounded list, status, cancel and immutable result reads. Scan inputs require sorted unique tool IDs; ordering is checked by the queue in addition to the schema's unique-items constraint. Job status separates execution admission from terminal scan status; cancellation does not assert cleanup. See ADR 036.
