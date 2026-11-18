# ADR 061: Read-only connector credentials and the local MCP bridge

Status: implemented; unit-tested and validated with the real bridge binary against a local stack. Desktop-app GUI compatibility is not claimed until tested in each app.

## Problem

The v4 manual (F7, X-018, B-036, INT-09) requires that installed desktop AI apps can read redacted Aegis evidence through MCP without Aegis receiving their credentials and without any MCP path able to change live configuration. The legacy `connections/invites/consents/handoffs/drafts` tables had no implementation.

## Decision

Migration 015 adds `connector_credentials` (`id`, `owner`, `name`, `token_hash` unique, `scope` fixed to `read_defence_v1`, `state` active/revoked, `created_at`, `expires`, `last_used`). Triggers make identity, scope, expiry and hash immutable and revocation one-way. Tokens are `aegis_ct_` + 32 random bytes in hex; only the SHA-256 is stored, and the token is returned once on creation. Lifetime is 1–720 hours. Issue and revoke commit atomically with audit records.

Any API request carrying `Authorization` is handled as a connector request: before routing, the method must be GET and the path must match an explicit allowlist (`/system/status`, `/sites`, `/sites/{id}/{incidents,endpoints,policy,events}`, `/incidents/{id}`, `/incidents/{id}/{assessment,proposals}`, `/ai/status`, `/findings/catalogue`, `/desktop/handoffs/{id}`). Everything else returns 403 without reaching a handler, and a bearer header never combines with an owner session. Connector management (`GET/POST /connectors`, `POST /connectors/{id}/revoke`) requires an owner session and CSRF token.

Offline restore revokes connector credentials from schema 15 onward. See the recovery runbook for supported schema versions.

`controller/cmd/aegis-mcp` is a dependency-free stdio MCP server (JSON-RPC 2.0; `initialize`, `ping`, `tools/list`, `tools/call`). It exposes eight retrieval tools annotated `readOnlyHint`, validates identifiers before building paths, prefixes every result with an untrusted-data notice, refuses plain HTTP to non-loopback hosts, refuses redirects, bounds responses to 512 KiB and requires a token file not readable by group or others.

## Consequences

- Mitigation proposals are visible to assistants but can only be approved in the console.
- Incidents are installation-wide (single owner), so any active connector of that owner can read every site's incidents.
- The bridge must be built locally (`make mcp-build`); signed release binaries are part of the supply-chain gate.

## Validation

Store tests check trigger immutability, unknown-scope refusal and one-way revocation. API tests check allowed reads, refusal of ten mutating/sensitive routes, dot-segment handling, malformed tokens, bearer-plus-cookie refusal, revocation and audit-chain integrity. Recovery tests check revocation on restore and legacy bundles. Bridge tests check protocol handling, read-only annotations, untrusted notice, identifier validation, unknown tools and unsafe configuration. `tests/integration/mcp_acceptance.py` drives the real binary over stdio against a local stack (`docs/evidence/mcp-acceptance.json`).


## Incident handoff increment (migration 021)

An owner session previews the minimum redacted incident bundle and binds approval to its exact hash and one active connector. Approval rechecks the digest and connector in one transaction, then stores the immutable snapshot and emits an audit event. Retrieval rechecks the connector and approval in the same transaction that marks delivery and records its audit event. Each handle is random, expires in at most five minutes and can be read once. Restore revokes unused and delivered approvals. The SQLite migration is additive and earlier migration bodies are preserved.

The preview excludes free text, raw request identifiers, routes, query values, headers, and client or path pseudonyms. Existing connector scopes retain their documented reads. A scoped pairing protocol and GUI interoperability with installed desktop apps remain open.


## Investigation draft increment (migration 022)

The owner may grant a single draft submission when approving a handoff. Existing approvals default to export only. The connector must first retrieve the snapshot, then submit before the original deadline. The draft transaction checks the original owner and connector, live consent, the approved snapshot digest, evidence references, and the idempotency key. A retained draft is initially unverified. Its content and provenance are immutable. The owner alone can dismiss it. Connector status calls return the draft identifier and review state for the original credential.

Restoring the database preserves drafts as review history and invalidates the connector and handoff used to create them. Proposed steps remain plain text in the console. Reports do not authorize scanner execution, policy changes, or remediation.
