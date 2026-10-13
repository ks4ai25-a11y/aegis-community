# Aegis v4 implementation status

Specification: `Aegis_Community_OSS_First_Engineering_Master_Manual_v4.md`, 12 October 2026. Master Parts A–L supersede conflicting preserved v3.2 contracts.

This repository is unfinished engineering work. No public-beta, production-safety, external-audit, scanner-support or desktop-GUI compatibility claim is made.

## Capability gates

| Capability | Current implementation | Acceptance state |
| --- | --- | --- |
| C0 defence foundation | Pinned Caddy/Coraza/CRS, telemetry sanitizer, controller, console, typed policies, isolated WAF fixture | Local ARM64 demo acceptance passed; broader gates pending |
| C1 security research | Bounded parsers, pinned images, fixed invocation plans and owner-scoped provisioned repository maps | Real Semgrep CE / Gitleaks / Syft / Bandit fixture runs pass; OSV / Trivy honestly reject missing offline databases |
| C2 closed loop | Trusted synthetic tenant challenge with correct, incorrect and overbroad variants | Six HTTP controls pass for correct variant; full patch/VM/AI orchestration pending |
| C3 operational release | Supply chain, full fault/restore tests, independent installations and security review | Not implemented |
| Desktop AI apps | UI identifies unverified integrations | Pairing, MCP and real GUI acceptance pending |

## Required v4 architecture changes

1. Typed deployer separated; controller gateway socket removed. Independent security review and stronger approval receipts remain.
2. Gateway-local active configuration persisted by deployer; container restart acceptance passed.
3. Durable scoped WAF jobs and generated research bindings added. Provisioned read-only repository registration added; durable scanner jobs, complete contract catalogue and scope integration for policy preview remain.
4. Six real pinned images now exercised offline. Provision and age-check OSV/Trivy caches, add adversarial golden cases and stronger pin/signature review.
5. Add isolated synthetic org_red/org_blue reproduction and code-fix regression evidence; reject an overbroad mitigation that breaks benign access.
6. Add findings, investigations, jobs and provenance views, then optional scoped AI/MCP connections.
7. Complete all twelve H7 release gates. Independent installation, legal review, provider GUI testing and independent security sign-off remain actual external requirements.

Security-sensitive changes require ADRs and independent review before public release. Test results must be recorded as observed; no unchecked gate is marked passed.

## Observed acceptance evidence

`docs/evidence/demo-acceptance.json` records the real local container run. It covers expected CRS 942100 correlation, privacy canaries, protected benign controls, idempotent activation, controller loss, gateway restart, rollback and inspected mounts/networks. It is not an external audit or a complete H7 pass.

`docs/evidence/scanner-acceptance.json` records pinned image and input identity for ten real static fixture runs. `docs/evidence/tenant-owner-fix.json` records six declared tenant HTTP controls and the embedded implementation digest. These remain narrow fixture claims.

`docs/evidence/scoped-jobs-acceptance.json` records real durable job execution, request-budget enforcement, running revocation, controller SIGKILL/lease timeout, and owner-bound report persistence. Scope grants currently authorize only the fixed bundled test_lab. Readiness sends no HTTP probe outside the four-request corpus; execution is bounded by grant expiry. The fixture digest covers the corpus, while stronger origin artifact binding remains pending.

`contracts/openapi-research.json` generates Go/Python/TypeScript clients for the implemented repository and scoped research endpoints. The console uses the generated client. `docs/evidence/contract-acceptance.json` records live payload and negative-schema checks. These are not the entire v4 API surface.

Provisioned repository records and immutable application maps are integrated with generated clients and the console. Confined reads reject path escapes, symlink/FIFO replacements and resource overruns. Private source snapshots are implemented; larger asynchronous inventory and durable scanner jobs remain required. See ADR 015 and the repository operator guide.

`docs/evidence/repository-acceptance.json` records live provisioned mount registration, matching source file hashes, stable reconnect identity, host-path/URL rejection and the controller read-only source mount. `ApplicationMapV1` and repository records pass live Draft 2020-12 schema checks. Controller crash/lease regressions still pass after migration 3.

Private source snapshots and an operator-launched offline executor now bind actual input files, tool/rule/guard identities and fixed argv. An independent container guard enforces time/output limits and verifies mounted input bytes. Fsynced journals and kernel leases support explicit host crash workspace recovery, bound to the original local engine identity. Durable controller scanner jobs, automatic recovery and offline advisory database provisioning remain incomplete. See ADR 016 and the offline scanner operator guide.

`docs/evidence/snapshot-scanner-acceptance.json` validates actual guarded executions, file/tool/rule identities and generated schemas. Semgrep/Gitleaks seeded/safe pairs and Syft package coordinates pass; missing OSV/Trivy databases remain errors. Guard crash evidence is recorded separately and does not complete H7 isolation review.

Research scope and job state changes now commit atomically with their audit records. SQLite audit-failure injection checks draft/approval/enqueue/claim/cancel/revoke/finish/recovery rollback, including reserved request budget and report ownership. Corrupted job or policy identity is refused before worker claim. See ADR 017; this is a prerequisite for, not completion of, durable scanner orchestration.

`docs/evidence/research-audit-acceptance.json` records all ten audit-failure/corruption checks with source hashes. The rebuilt local controller passes the scoped-job suite, including persisted claim/reconciliation audit events and chain verification after SIGKILL.

Parser 1.1 rejects ambiguous/oversized JSON before decoding, separates dependency IDs by package/version, preserves declared package names, and refuses configuration findings without separate consent. Ten real pinned fixture runs and a bounded six-parser fuzz run passed; older parser 1.0 receipts remain schema-compatible. Comprehensive ecosystem/rule coverage and durable scanner scheduling remain unfinished. See ADR 018.

GitHub CI run 38333989577 passed both source and disposable trusted-demo jobs on Ubuntu 24.04 for commit 2a0df557838fc1851819b30ac4f70dcf16a374f7. This includes the Go race/console checks, research guard builds and real demo/scoped-job/repository journeys. `docs/evidence/hosted-ci-2a0df55.json` records the exact commit and job URLs; it is not independent security sign-off or a complete release-gate pass.

The operator scanner CLI now refuses a second run while its enrolled registry contains a live or unrecovered session. Explicit recovery must confirm the original container is absent before admission resumes. Durable controller scheduling and cross-operator host admission remain unfinished.

Bandit 1.9.4 now executes through the pinned-image, private-snapshot guard. The default fixed profile ignores repository INI and inline suppression settings; AST-only canary and syntax-error controls pass. New execution receipts record parser identity even without findings. See ADR 019 and `docs/evidence/bandit-acceptance.json`; this is not complete Python coverage, a publisher-signature review or durable scan orchestration.

Parser 1.2 integrates bounded finding aggregation into every parsed result. Each new source retains its normalized severity claim; dependency identities can agree across tools only within the same application/repository/snapshot/package/version/advisory/lockfile scope. Tool namespaces remain separate for static patterns. Provenance overflow becomes tool_error, and aggregation never promotes T0 claims. See ADR 020; durable finding history, full AST/advisory canonicalization and investigation UI remain unfinished.

An internal durable offline scanner request component now binds owner/repository/map/tool-lock identity with atomic enqueue/cancel auditing and bounded retention. Migration 4 upgrades the prior database without changing deployed migration checksums. Restart, concurrency, ownership and audit-failure tests cover this foundation. See ADR 021; scanner API, trusted worker dispatch/leases, expiry enforcement, receipt ingestion and console integration are still unfinished.

The internal scanner queue now has atomic single-admission claims, hashed random lease capabilities, bounded renewal/deadlines, queued expiry and crash reconciliation. Expired or failed execution retains cleanup_required admission instead of treating a terminal job as proof that the container stopped. See ADR 022. Actual enrolled-worker dispatch, verified cleanup release, immutable scanner receipt ingestion and API/UI integration remain unfinished.
