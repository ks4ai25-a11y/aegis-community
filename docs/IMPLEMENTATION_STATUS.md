# Aegis v4 implementation status

Specification: `Aegis_Community_OSS_First_Engineering_Master_Manual_v4.md`, 12 October 2026. Master Parts A–L supersede conflicting preserved v3.2 contracts.

This repository is unfinished engineering work. No public-beta, production-safety, external-audit, scanner-support or desktop-GUI compatibility claim is made.

## Capability gates

| Capability | Current implementation | Acceptance state |
| --- | --- | --- |
| C0 defence foundation | Pinned Caddy/Coraza/CRS, telemetry sanitizer, controller, console, typed policies, isolated WAF fixture | Local ARM64 demo acceptance passed; broader gates pending |
| C1 security research | Bounded parsers, pinned images, fixed invocation plans and owner-scoped provisioned repository maps | Real Semgrep CE / Gitleaks / Syft fixture runs pass; OSV / Trivy honestly reject missing offline databases |
| C2 closed loop | Trusted synthetic tenant challenge with correct, incorrect and overbroad variants | Six HTTP controls pass for correct variant; full patch/VM/AI orchestration pending |
| C3 operational release | Supply chain, full fault/restore tests, independent installations and security review | Not implemented |
| Desktop AI apps | UI identifies unverified integrations | Pairing, MCP and real GUI acceptance pending |

## Required v4 architecture changes

1. Typed deployer separated; controller gateway socket removed. Independent security review and stronger approval receipts remain.
2. Gateway-local active configuration persisted by deployer; container restart acceptance passed.
3. Durable scoped WAF jobs and generated research bindings added. Provisioned read-only repository registration added; durable scanner jobs, complete contract catalogue and scope integration for policy preview remain.
4. Five real pinned images now exercised offline. Provision and age-check OSV/Trivy caches, add adversarial golden cases and stronger pin/signature review.
5. Add isolated synthetic org_red/org_blue reproduction and code-fix regression evidence; reject an overbroad mitigation that breaks benign access.
6. Add findings, investigations, jobs and provenance views, then optional scoped AI/MCP connections.
7. Complete all twelve H7 release gates. Independent installation, legal review, provider GUI testing and independent security sign-off remain actual external requirements.

Security-sensitive changes require ADRs and independent review before public release. Test results must be recorded as observed; no unchecked gate is marked passed.

## Observed acceptance evidence

`docs/evidence/demo-acceptance.json` records the real local container run. It covers expected CRS 942100 correlation, privacy canaries, protected benign controls, idempotent activation, controller loss, gateway restart, rollback and inspected mounts/networks. It is not an external audit or a complete H7 pass.

`docs/evidence/scanner-acceptance.json` records pinned image and input identity for ten real static fixture runs. `docs/evidence/tenant-owner-fix.json` records six declared tenant HTTP controls and the embedded implementation digest. These remain narrow fixture claims.

`docs/evidence/scoped-jobs-acceptance.json` records real durable job execution, request-budget enforcement, running revocation, controller SIGKILL/lease timeout, and owner-bound report persistence. Scope grants currently authorize only the fixed bundled test_lab. Readiness sends no HTTP probe outside the four-request corpus; execution is bounded by grant expiry. The fixture digest covers the corpus, while stronger origin artifact binding remains pending.

`contracts/openapi-research.json` generates Go/Python/TypeScript clients for the implemented repository and scoped research endpoints. The console uses the generated client. `docs/evidence/contract-acceptance.json` records live payload and negative-schema checks. These are not the entire v4 API surface.

Provisioned repository records and immutable application maps are integrated with generated clients and the console. Confined reads reject path escapes, symlink/FIFO replacements and resource overruns. Source snapshots, larger asynchronous inventory and durable scanner jobs remain required. See ADR 015 and the repository operator guide.

`docs/evidence/repository-acceptance.json` records live provisioned mount registration, matching source file hashes, stable reconnect identity, host-path/URL rejection and the controller read-only source mount. `ApplicationMapV1` and repository records pass live Draft 2020-12 schema checks. Controller crash/lease regressions still pass after migration 3.

Private source snapshots and an operator-launched offline executor now bind actual input files, tool/rule/guard identities and fixed argv. An independent container guard enforces time/output limits and verifies mounted input bytes. Durable controller scanner jobs, host crash workspace recovery and offline advisory database provisioning remain incomplete. See ADR 016 and the offline scanner operator guide.

`docs/evidence/snapshot-scanner-acceptance.json` validates actual guarded executions, file/tool/rule identities and generated schemas. Semgrep/Gitleaks seeded/safe pairs and Syft package coordinates pass; missing OSV/Trivy databases remain errors. Guard crash evidence is recorded separately and does not complete H7 isolation review.
