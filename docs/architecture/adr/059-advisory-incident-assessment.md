# ADR 059: Advisory incident assessment with deterministic default and optional local model

Status: implemented; unit-tested and validated against a local Ollama server. MCP access and persisted assessment history remain open.

## Problem

The v4 manual (E5, F6) requires an AI Blue investigator that consumes a bounded, sanitized dossier and produces `IncidentAssessmentV1`, with deterministic work continuing when no provider is available. Community must stay usable with zero spend, so no paid API or account can be required, and model output must never become enforcement.

## Decision

`controller/internal/assess` builds a dossier from local storage only: incident and detector record, up to 50 linked sanitized events, site mode/CRS/exclusion count, top 20 observed routes and the related open-incident count. The `Deterministic` assessor maps each detector to fixed facts, hypotheses, recommendations and tests, and always states the standing evidence limits.

An optional model is configured by the owner through `AEGIS_AI_PROVIDER` (`none` default, `ollama`, `openai_compatible`), `AEGIS_AI_URL`, `AEGIS_AI_MODEL` and an optional `AEGIS_AI_KEY_FILE`. Invalid configuration is rejected at start-up and falls back to `none`. Requests use temperature 0, a JSON-schema structured-output grammar that bounds list sizes and string lengths, a 180-second default limit (`AEGIS_AI_TIMEOUT_SECONDS`, 10–600), no redirects and a 256 KiB response limit. The system instruction declares the delimited dossier untrusted data and forbids following instructions inside it.

`Parse` treats the reply as untrusted: one JSON object, at most 64 KiB; enums are checked; evidence references not present in the dossier are removed; text is stripped of control characters and truncated; list lengths are capped; a fixed advisory uncertainty is appended. Unusable output or an unreachable model yields the deterministic assessment with `fallback_reason`.

The API adds `GET /api/v1/ai/status` (no secrets), and `POST`/`GET /api/v1/incidents/{id}/assessment`. POST requires the owner session and CSRF token, runs one assessment at a time (429 otherwise) and records `incident.assessed` in the audit chain with the dossier digest, model and fallback reason. Results are cached in memory (bounded) rather than persisted, avoiding a migration while migration 014 is reserved; they are reproducible from the dossier.

`deploy/compose.ai-local.yaml` adds a digest-pinned Ollama server running as UID 10001 with all capabilities dropped and a read-only root, on an internal network shared only with the controller. Model download is a separate explicit one-shot job, the only component given internet access.

## Consequences

- Assessments are proposals; recommendation kinds are limited to `investigate`, `exclusion`, `protect`, `observe` and `rollback`, and none is executed.
- Small local models can be wrong. Provenance always names the assessor and model.
- The controller already has outbound network access in the reference deployment; a misconfigured remote `AEGIS_AI_URL` would send dossiers off-host. The dossier contains no raw identifiers, and the console shows the configured endpoint host.

## Validation

`controller/internal/assess` tests cover every detector template, reference/enum/control-character filtering, malformed and oversized output, a mock Ollama server receiving the delimited dossier with an injection string and guardrails, unreachable-model and disabled fallbacks, configuration rejection (file URLs, embedded credentials, unknown provider, missing model) and dossier construction from a real store. Live evidence is in `docs/evidence/ai-assessment-acceptance.json`.
