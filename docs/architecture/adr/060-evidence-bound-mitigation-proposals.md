# ADR 060: Evidence-bound mitigation proposals

Status: implemented; unit-tested and validated live against the bundled fixture. Code-patch proposals (D8 for source findings) remain open.

## Problem

Incidents and assessments told an owner what happened but not what concrete change to review. The v4 lifecycle (D8, E6) requires proposals that are data, show rationale, impact, evidence, tests and side effects, and never apply themselves. A useful exclusion needs the matched parameter *name*, which the sanitizer previously discarded together with the value.

## Decision

The gateway sanitizer extracts only the argument name from Coraza's `found within ARGS[_GET|_POST]:<name>` match data (`target: "ARGS:<name>"`, name pattern `[a-zA-Z][a-zA-Z0-9_]{0,31}`). Values, headers, cookies and other collections are never kept. Ingest accepts only that exact form.

`controller/internal/propose` produces `MitigationProposalV1` records for CRS incidents (DET-01) only:

- **exclusion** (P3) — the first matched rule, method, exact route and parameter from paired WAF/access evidence, added to the site's exclusions. It is proposed only when the full candidate passes `policy.Validate` (so templated routes, unsupported rules and anomaly-scoring rules are refused and explained).
- **protect** (P2) — the site's mode changed to Protect when it is in Observe.

Each proposal is a complete candidate policy revision with `parent_revision` set to the active digest, a content-derived `proposal_id`, rationale, expected impact, side effects, evidence references and tests. Behavioural detectors (DET-02…06) remain advisory and receive an explanation instead. `GET /api/v1/incidents/{id}/proposals` returns proposals and `not_proposed` reasons. The console sends a chosen candidate through the existing pinned validation and isolated fixture preview, and only an explicit acknowledgement plus **Approve and activate** submits it.

## Consequences

- An exclusion that would remove the bundled negative control fails the fixture preview and cannot be activated from the console, as the live run shows.
- Proposals are recomputed on demand from retained evidence; when evidence ages out, the reason is shown.

## Validation

`controller/internal/propose` tests cover valid demo candidates, templated routes, missing parameter names, anomaly-scoring rules and advisory-only detectors. `gateway/telemetry` tests cover name-only extraction and refusal of headers, invalid and oversized names. `tests/integration/assessment_acceptance.py` (`docs/evidence/ai-assessment-acceptance.json`) records the unsafe exclusion failing the fixture, the Protect proposal passing it and the active revision unchanged.
