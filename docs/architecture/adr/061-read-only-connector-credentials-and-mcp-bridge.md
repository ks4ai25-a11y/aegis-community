# ADR 061: Read-only connector credentials and the local MCP bridge

Status: implemented; unit-tested and validated with the real bridge binary against a local stack. Desktop-app GUI compatibility is not claimed until tested in each app.

## Problem

The v4 manual (F7, X-018, B-036, INT-09) requires that installed desktop AI apps can read redacted Aegis evidence through MCP without Aegis receiving their credentials and without any MCP path able to change live configuration. The legacy `connections/invites/consents/handoffs/drafts` tables had no implementation.

## Decision

Migration 015 adds `connector_credentials` (`id`, `owner`, `name`, `token_hash` unique, `scope` fixed to `read_defence_v1`, `state` active/revoked, `created_at`, `expires`, `last_used`). Triggers make identity, scope, expiry and hash immutable and revocation one-way. Tokens are `aegis_ct_` + 32 random bytes in hex; only the SHA-256 is stored, and the token is returned once on creation. Lifetime is 1–720 hours. Issue and revoke commit atomically with audit records.

Any API request carrying `Authorization` is handled as a connector request: before routing, the method must be GET and the path must match an explicit allowlist (`/system/status`, `/sites`, `/sites/{id}/{incidents,endpoints,policy,events}`, `/incidents/{id}`, `/incidents/{id}/{assessment,proposals}`, `/ai/status`, `/findings/catalogue`). Everything else returns 403 without reaching a handler, and a bearer header never combines with an owner session. Connector management (`GET/POST /connectors`, `POST /connectors/{id}/revoke`) requires an owner session and CSRF token.

Offline restore revokes connector credentials for version-15 databases; recovery bundles accept schema versions 13–15.

`controller/cmd/aegis-mcp` is a dependency-free stdio MCP server (JSON-RPC 2.0; `initialize`, `ping`, `tools/list`, `tools/call`). It exposes seven read-only tools annotated `readOnlyHint`, validates identifiers before building paths, prefixes every result with an untrusted-data notice, refuses plain HTTP to non-loopback hosts, refuses redirects, bounds responses to 512 KiB and requires a token file not readable by group or others.

## Consequences

- Mitigation proposals are visible to assistants but can only be approved in the console.
- Incidents are installation-wide (single owner), so any active connector of that owner can read every site's incidents.
- The bridge must be built locally (`make mcp-build`); signed release binaries are part of the supply-chain gate.

## Validation

Store tests check trigger immutability, unknown-scope refusal and one-way revocation. API tests check allowed reads, refusal of ten mutating/sensitive routes, dot-segment handling, malformed tokens, bearer-plus-cookie refusal, revocation and audit-chain integrity. Recovery tests check revocation on restore and legacy bundles. Bridge tests check protocol handling, read-only annotations, untrusted notice, identifier validation, unknown tools and unsafe configuration. `tests/integration/mcp_acceptance.py` drives the real binary over stdio against a local stack (`docs/evidence/mcp-acceptance.json`).
