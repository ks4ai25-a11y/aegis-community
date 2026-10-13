# Contracts and generated research clients

Draft 2020-12 schemas currently cover demo policy, normalized source findings, exact provisioned repository records, application maps, source snapshot manifests, offline scanner execution receipts, fixed scope grants, scope approval, durable verification input/status, bounded verification reports and typed errors. `openapi-research.json` is OpenAPI 3.1 for the implemented repository/scope/job/report endpoints. It does not advertise unsupported v4 app/scanner/AI endpoints.

Generate bindings with `python3 scripts/generate_contracts.py`, then clients with `python3 scripts/generate_research_api.py`. Go, Python and TypeScript clients derive from the OpenAPI operations; the console Repositories and Verify pages uses the generated client. Go/Python admin clients restrict destinations to loopback, bound responses and refuse redirects. Supply an existing owner session and CSRF token; credentials are held in memory and never logged by these clients.

`tests/integration/contract_acceptance.py` checks actual local job, grant, report and finding payloads using pinned jsonschema 4.26.0 and tests malformed/overbroad examples. `samples/` contains sanitized synthetic runtime goldens, without owner session credentials. Generated client tests cover request shapes and destination/redirect restrictions.

Runtime typed decoding rejects unknown/duplicate fields. Additional semantic validators enforce ownership, expiry, total request budgets, immutable digests, policy constraints, leases and actual baseline/candidate evidence. Schema/type conformance alone does not grant authority or establish a security claim.

Still required: the complete v4 contract catalogue and API surface, runtime JSON Schema validation where appropriate, generated core/AI clients, version negotiation, compatibility tests and independent contract review. Aegis's invalid-domain schema identifiers are local identifiers, not remote services.

`SourceSnapshotManifestV1` and `ScannerExecutionV1` describe the operator-only execution boundary; no unsupported controller scan endpoint is advertised. `snapshot_scanner_acceptance.py` checks real pinned-image receipts against Draft 2020-12. Whole-source retention, durable scanner orchestration and independent provenance review remain incomplete.
