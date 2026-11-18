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

The preview excludes free text, raw request identifiers, routes, query values, headers, and client or path pseudonyms. Existing connector scopes retain their documented reads. The scoped pairing protocol is described below. GUI interoperability with installed desktop apps remains open.


## Investigation draft increment (migration 022)

The owner may grant a single draft submission when approving a handoff. Existing approvals default to export only. The connector must first retrieve the snapshot, then submit before the original deadline. The draft transaction checks the original owner and connector, live consent, the approved snapshot digest, evidence references, and the idempotency key. A retained draft is initially unverified. Its content and provenance are immutable. The owner alone can dismiss it. Connector status calls return the draft identifier and review state for the original credential.

Restoring the database preserves drafts as review history and invalidates the connector and handoff used to create them. Proposed steps remain plain text in the console. Reports do not authorize scanner execution, policy changes, or remediation.


## Local device pairing (migration 023)

The owner creates a five-minute invitation and selects a 15-, 30- or 60-minute credential lifetime. The local bridge claims the invitation with a private device proof and a hash of its locally generated credential. The fingerprint binds the invitation ID, device proof and credential hash. The owner compares it against the value shown by the bridge. The device proves possession again after confirmation, and only then does the controller activate the credential. The response contains connection metadata, never the token.

Paired token hashes are domain separated and require a corresponding immutable scope mapping. Paired credentials can read authenticated connector status and retrieve explicitly approved handoffs. A device-level draft permission and a separate handoff-level approval are both required to submit a draft. Revocation stops access and restore erases outstanding invitations. This path supports explicit local configuration and private file storage. Installed app interoperability, OS-specific keychain integration, and renewal are separate acceptance work.


## Compiled bridge acceptance

`make desktop-verify` runs the compiled stdio bridge against an isolated real controller and migrated SQLite database. It requires owner fingerprint confirmation, a scoped authenticated status check, exact single delivery, idempotent draft submission with the approved bundle digest, owner dismissal, and denial on the still-running bridge after revocation. It also verifies protocol negotiation and admission of tool calls only after initialization. The source workflow runs this gate before browser checks. This establishes executable interoperability with the controller. App-specific GUI acceptance remains separate.

## Owner-approved renewal (migration 024)

An authenticated owner may approve rotation for an active paired credential. The approval is pinned to that credential and expires in at most five minutes. The bridge syncs a private replacement file before submitting its hash. An audited transaction swaps the token and expiry under the existing connector ID and scope. The old token can only recover the matching receipt inside that approval window. Already revoked credentials and retired hashes cannot be restored as current tokens.

The bridge installs the replacement atomically after checking that it authenticates. The compiled acceptance journey simulates a lost receipt after commit and verifies that a restarted bridge retains the device identity. Offline restore preserves rotation history, cancels pending grants, and revokes all connectors.
