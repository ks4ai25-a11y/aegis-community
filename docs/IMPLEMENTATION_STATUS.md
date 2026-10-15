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

Parser 1.1 rejects ambiguous/oversized JSON before decoding, separates dependency IDs by package/version, preserves declared package names, and refuses configuration findings without separate consent. Ten real pinned fixture runs and a bounded six-parser fuzz run passed; older parser 1.0 receipts remain schema-compatible. Comprehensive ecosystem/rule coverage and end-to-end scanner worker orchestration remain unfinished. See ADR 018.

GitHub CI run 38333989577 passed both source and disposable trusted-demo jobs on Ubuntu 24.04 for commit 2a0df557838fc1851819b30ac4f70dcf16a374f7. This includes the Go race/console checks, research guard builds and real demo/scoped-job/repository journeys. `docs/evidence/hosted-ci-2a0df55.json` records the exact commit and job URLs; it is not independent security sign-off or a complete release-gate pass.

The operator scanner CLI now refuses a second run while its enrolled registry contains a live or unrecovered session. Explicit recovery must confirm the original container is absent before admission resumes. The controller has durable internal queue/lease scheduling; actual worker execution and cross-operator host admission remain unfinished.

Bandit 1.9.4 now executes through the pinned-image, private-snapshot guard. The default fixed profile ignores repository INI and inline suppression settings; AST-only canary and syntax-error controls pass. New execution receipts record parser identity even without findings. See ADR 019 and `docs/evidence/bandit-acceptance.json`; this is not complete Python coverage, a publisher-signature review or durable scan orchestration.

Parser 1.2 integrates bounded finding aggregation into every parsed result. Each new source retains its normalized severity claim; dependency identities can agree across tools only within the same application/repository/snapshot/package/version/advisory/lockfile scope. Tool namespaces remain separate for static patterns. Provenance overflow becomes tool_error, and aggregation never promotes T0 claims. See ADR 020; durable finding history, full AST/advisory canonicalization and investigation UI remain unfinished.

An internal durable offline scanner request component now binds owner/repository/map/tool-lock identity with atomic enqueue/cancel auditing and bounded retention. Migration 4 upgrades the prior database without changing deployed migration checksums. Restart, concurrency, ownership and audit-failure tests cover this foundation. See ADR 021; scanner API, receipt ingestion and console integration remain unfinished. Internal worker dispatch/leases and expiry enforcement are implemented through ADRs 022–026.

The internal scanner queue now has atomic single-admission claims, hashed random lease capabilities, bounded renewal/deadlines, queued expiry and crash reconciliation. Expired or failed execution retains cleanup_required admission instead of treating a terminal job as proof that the container stopped. See ADR 022. Actual pinned-tool execution through the enrolled worker, verified cleanup release, immutable scanner receipt ingestion and API/UI integration remain unfinished.

Scanner worker roles now bind a connected provisioned-mount owner, expiring hashed credential and immutable enrollment ID. A local aegisctl command delivers credentials to a new private file; transactional claim/renewal checks close authentication/revocation races. Revocation requests cancellation while retaining cleanup admission. See ADR 023 and the scanner-worker operator guide. The private transport is implemented through ADR 024; the runnable worker service, scanner API, receipt ingestion and verified cleanup release remain unfinished.

A dedicated authenticated Unix scanner channel now supports identity, owner-bound claim, lease guard and finite failure operations, with bounded requests and private socket lifecycle recovery. The controller copies/validates the tool lock and reconciles expiry independently of workers; the local CLI can probe enrollment without exporting credentials. See ADR 024. Actual scanner worker execution, receipt/finding ingestion, verified cleanup release, owner API/UI and Windows/remote worker transport remain unfinished.

The alpha scanner-side private client now implements identity, claim, guard and finite failure requests without a controller database dependency. It validates owner/pin/request/map bindings and deadlines, bounds and strictly decodes responses, rereads private credentials, and refuses proxy/redirect/TCP transport. ADR 025 records its local Unix protocol-fixture evidence. The actual worker execution loop, deployed client/server interoperability acceptance, result ingestion, verified cleanup release and owner-facing scanner API/UI remain unfinished.

The alpha client now has a cancellation-aware lease keeper with initial/final guard checks, original-deadline enforcement, five-second renewal and synchronous task/renewal joining. A separate test-only module connects the real client to the real controller handler, enrollment registry, repository registry and migrated SQLite queue over private Unix sockets. It verifies lifecycle, failure replay, withdrawal, expiry and retained cleanup admission; `make test` includes it. ADR 026 limits this evidence to component interoperability and cooperative task control. Full scanner execution, normalized receipt ingestion, cleanup confirmation, deployed worker acceptance and owner scanner API/UI remain unfinished.

Scanner evidence data and fixed invocation construction now live in a shared package that contains no executor/database/network access. The alpha parser/executor retain compatible aliases. Canonical receipt decoding and context-bound normalization reject tool/pin/map/source/proof/coverage violations, remove free presentation text, preserve T0 structured provenance and classify unproven OSV/Trivy freshness as `completed_stale_db`. A real six-tool controller-claim integration exercises all six actual adapters through this contract. ADR 027 records the scope. Durable receipt ingestion, append-only storage, actual worker execution, independent cleanup release and the remaining manual/release requirements remain unfinished.

Migration 7 adds an internal append-only owner/job/tool receipt ledger. New writes require live enrolled-worker/lease/map/lock/pin authority; normalized receipts and audit events commit atomically. Exact immutable replay survives restart/lease expiry/pin rotation without renewing execution, and conflicting replay or cross-owner access is refused. Reads verify document digests and relations; storage has explicit record/byte admission bounds. ADR 028 records the local-host trust boundary. Private transport ingestion and the client submission method are implemented through ADR 029. Actual worker execution/submission lifecycle, independent cleanup confirmation, terminal aggregation, archive rotation and owner scanner API/UI remain unfinished.

Authenticated private Unix receipt submission now connects the alpha client to the controller ledger without a worker database dependency. The shared bounded envelope rejects hostile/unknown owner fields; new writes and replay retain transactional authority/immutability checks. The client normalizes before upload and verifies the exact owner/job/request-bound acknowledgement digest. All six actual adapter fixtures submit/replay through the real private handler, leaving the job running and cleanup unconfirmed. ADR 029 records the scope. Runnable worker execution, cleanup proof/release, suite completion, owner scanner API/UI and the remaining v4 requirements remain unfinished.


## Current worker execution increment (ADR 030)

The native `worker-once` command now joins the owner-bound private claim, lease renewal, confined approved-source capture, fixed offline executor and authenticated receipt submission. Per-tool journals preserve original container/engine identity; the local tool lock must match the authorized claim before launch. Real pinned Bandit and sequential Bandit/Gitleaks fixtures store receipts; missing offline OSV database support remains a tool error. Source changes are refused before execution.

Successful invocation reports `awaiting_controller_finalization`. Controller terminal aggregation, independent cleanup confirmation and admission release remain absent; this is not a reusable completed scanner service. Operator-UID component fixtures do not establish deployment access to the Compose UID 10001 socket. Background worker deployment, recovery, offline databases, full findings/investigation UI, disposable VM execution, AI/MCP/desktop integrations, supply-chain review and independent H7 release gates remain required. Historical sections above retain the scope of earlier increments. Evidence: `docs/evidence/scanner-worker-execution-acceptance.json`.


## Current terminal scanner results (ADR 031)

Scanner finish now derives immutable owner/job-bound result indexes from every requested accepted receipt. Partial/stale/error flags remain independent; overall status conservatively prioritizes tool error, partial, stale and completed. Migration 8 commits the result, terminal job state and audit atomically while retaining cleanup admission. Native one-shot execution prints the result and exact terminal scan status; `tool_error` exits nonzero. This supersedes ADR 030's temporary pending-finalization status.

Real Bandit, Bandit/Gitleaks and Bandit/OSV/Trivy suites pass terminal derivation; the missing offline databases remain errors and do not stop collection of later requested static tools when cleanup is safe. Actual six-adapter parser fixtures preserve stale-database uncertainty through private finish/replay. Generated suite schemas and bindings describe these bounded result indexes. Evidence: `docs/evidence/scanner-finalization-acceptance.json`.

Independent cleanup verification/admission release, deployable worker pairing and background recovery remain unfinished. Public scanner result APIs/UI, full finding aggregation/investigations, offline databases, disposable VM execution, AI/MCP/desktop integration, supply-chain review and independent H7 gates remain required. No reusable scanner-service or production-release claim is made.


## Current prelaunch journal increment (ADR 032)

The private worker records one immutable controller launch intent per selected tool before the fixed Docker command. Local workspace fsync precedes controller commit, and the acknowledgement binds the prepared pin, engine, namespace, snapshot and original job deadline. Executed receipts must match the attempt; a preflight receipt cannot erase it. Migration 9 quarantines legacy dispatches without inventing history, and native claims require launch protocol 1.0. Live authority is required even for exact launch replay.

Real scanner fixtures bind launch records to their durable receipts and terminal results, including a seeded T0 Bandit claim and honest offline database errors. Generated launch schemas describe bounded metadata, not a public launch API. Evidence: `docs/evidence/scanner-launch-acceptance.json`.

Independent cleanup/admission release remains unfinished. Crashes before the first launch record still need trusted workspace/capture namespace binding; zero records are not absence proof. Deployable/background worker pairing, public scanner result UI/API, full finding/investigation lifecycle, databases, disposable VM execution, AI/MCP/desktop integration, supply-chain/legal/security review and independent H7 gates remain required.

## Current capture reservations (ADR 033)

The supported static worker now commits an immutable owner/job/tool workspace reservation before creating a run directory or copying source. The callback holds local registry admission while validating the private acknowledgement; failure creates no source workspace. The fsynced local journal carries the reservation digest. Later launches must match the earlier workspace/registry/snapshot plan. Migration 10 quarantines older dispatches from new execution without rewriting their evidence or releasing admission.

Real private-channel crash fixtures verify acknowledgement loss after commit and capture-before-launch orphans. Pinned scanner fixtures bind reservations to actual launch/receipt/result records. Evidence: `docs/evidence/scanner-workspace-acceptance.json`. This supersedes ADR 032's supported-worker capture identification gap; an empty ledger still cannot prove absence for legacy or unsupported workers.

Independent cleanup/admission release, trusted namespace provisioning, incomplete-allocation recovery, late-start exclusion and deployable/background worker pairing remain required. Public scanner result API/UI, full findings/investigation lifecycle, offline databases, disposable VM execution, AI/MCP/desktop integration, supply-chain/legal/security review and independent H7 gates remain unfinished.

Hosted CI run 38412015332 exposed an asynchronous fixed-fixture telemetry race: the verifier returned after the first correlated rule (`920350`), before required SQLi rule `942100` drained. The verifier now waits within its existing bounded drain window for the expected correlated rule, deduplicates rule IDs and honors cancellation. It continues to fail without expected evidence; another request cannot supply it. Delayed-output regression tests cover the failure. This is a fixture evidence collection correction, not a relaxation of verification requirements.

## Current absolute scanner deadlines (ADR 034)

The current native worker passes the original controller job deadline into the rebuilt PID-1 guard. Expired startup refuses before reading source or spawning a scanner; valid execution uses the earlier remaining deadline/tool budget, including input validation. The executor checks expiry before source/Docker and again after prelaunch acknowledgement. Real guard-only probes and ordinary pinned scanner suites validate this increment. Evidence: `docs/evidence/scanner-absolute-deadline-acceptance.json`.

Cleanup admission remains held. Independent original-engine/registry verification, late queued-request exclusion, guard provenance binding and a separately authorized cleanup-release mechanism remain required. Historical relative-duration guards are not reinterpreted as absolute-expiry evidence. Full v4 worker deployment, UI, finding lifecycle, databases, disposable VM execution, desktop AI/MCP, supply-chain review and independent H7 release gates remain unfinished.

## Current controller-approved guard builds (ADR 035)

The private controller hashes its own packaged Linux AMD64/ARM64 guards after bounded ELF/Go build identity checks. Fresh dispatches bind that canonical set; claims return it to the enrolled worker. Launch schema 1.1 records the approved guard digest/architecture/protocol, and new executed receipts must match. Migration 11 preserves historical records and quarantines older dispatches with no invented build authority. Native and Docker guard builds use matching reproducibility flags.

Evidence: `docs/evidence/scanner-guard-binding-acceptance.json`. This binds local approved package identity to intent/evidence, not actual mounted/running bytes. Independent engine/registry/guard-mount verification, late-start exclusion, cleanup release and deployable worker pairing remain required. The remaining v4 result UI, findings/investigations, offline databases, disposable VM execution, AI/MCP/desktop integrations, signatures/supply-chain review and independent H7 release gates remain unfinished.

## Current owner scanner API (ADR 036)

Owner sessions can now enqueue/list offline scans, read job/admission status, cancel owned jobs and read revalidated immutable suite results through `/api/v1/scans`. OpenAPI and generated Go/Python/TypeScript clients cover these operations. The controller shares its startup-provisioned queue with the private worker channel; owner requests cannot supply worker authority, images, commands or cleanup assertions. Missing results remain explicit errors; T0/stale/partial/tool-error flags and cleanup holds survive HTTP reads. See ADR 036 and `docs/evidence/scanner-owner-api-acceptance.json`.

This completes the initial owner scanner request/result API, not the findings detail API or scanner console. Independent cleanup verification/release, worker deployment/socket pairing, background service operation, offline databases, disposable VM execution, AI/MCP/desktop integrations, supply-chain/legal/security review and independent H7 gates remain unfinished. Earlier sections describe historical increments and their then-current limits.

## Current scanner console (ADR 037)

The Scans page now connects the generated owner API to repository/tool/budget consent, exact retry after uncertain acknowledgement, bounded job history, cancellation, admission status and immutable T0 suite summaries. Result views preserve independent coverage/database/tool-error flags and reject direct or polled identity mismatches. Browser challenges cover stale responses and responsive layout; the explicit local live check queues/cancels a real safe-repository job without source execution. See ADR 037 and `docs/evidence/scanner-console-acceptance.json`.

Individual findings detail/deduplication UI, independent cleanup verification/release, deployable worker pairing/background execution, offline databases, VM execution, AI/MCP/desktop integrations and remaining H7 release gates remain unfinished. Earlier sections preserve the historical scope of their increments.

## Current static finding details (ADR 038)

Owner reads can now project normalized findings from a selected immutable scan through `/api/v1/findings?job_id=...`. Shared conservative deduplication retains original receipt/source/severity evidence; pages preserve T0/suspected/low-confidence semantics, independent coverage/error flags and strict count/byte bounds. The Scans console provides category/severity filters, bounded pages and source/version/receipt details, with stale/mismatched-response rejection and escaped text rendering. Five real adapter claims merge to four static records in the equivalent-dependency fixture; separate actual scanner fixtures remain distinct execution evidence. See ADR 038 and `docs/evidence/finding-projection-acceptance.json`.

This is selected-job finding projection, not a completed global catalogue or triage/proof workflow. Cross-job history, richer source/AST context, independent reproduction/remediation, cleanup verification/release, deployable workers, offline databases, VM isolation, AI/MCP/desktop integration, supply-chain review and independent H7 gates remain unfinished.

## Current original-engine observer (ADR 039)

A read-only operator path now compares an exact scanner container's original engine, selected image/command/sandbox settings, reported mount paths, guard bytes and source/rules snapshots against private launch context. Context export is owner checked, private and no-overwrite. Observation does not consume worker cleanup booleans, mutate engine/workspaces or release admission. Required metadata is bounded; missing safety fields cannot become confirmed false values. A real stopped-container fixture exercises the library/CLI, guard/root-profile refusal and absent-state uncertainty without starting a tool. See ADR 039 and docs/evidence/scanner-sandbox-observer-acceptance.json.

This is not completed independent cleanup verification: controller role authentication, registry/lease/incomplete-allocation checks, queued late-start exclusion and separately authorized atomic release are still required. The full remaining v4 scope and independent H7 gates remain active.

## Owner finding review increment (ADR 040)

Selected-job static finding pages can now show a separate owner assessment. GET/POST review operations bind owner, job, exact immutable result and normalized record. Schema 12 stores append-only decisions with a prior digest, expected revision, durable exact idempotent replay and the same transaction's audit record. Local rationale stays outside ordinary audit payloads and automatic model uploads. False-positive/risk decisions never promote T0, change source receipts/counts or release admission. The console validates response identities/digests and keeps uncertain retries stable.

Evidence and rollout checks are recorded in docs/evidence/finding-triage-acceptance.json: full source checks, six native scanner attempts, actual parser/HTTP review journeys, 16 browser fixtures, one deployed browser journey and 45 live demo checks passed. Cross-job catalogue/history, history browsing/export, richer investigation/proof/remediation workflows, independent cleanup/release, deployable workers, databases, VM execution, desktop AI/MCP and independent H7 gates remain unfinished.

## Scoped controller cleanup-context reader (ADR 041)

Schema 13 adds operator-enrolled scanner-cleanup-observer identities bound to one owner, engine and workspace-registry digest. They use separate domain-separated token hashes and cannot call worker operations. Context reads recheck live enrollment/scope in the same transaction as immutable launch/workspace metadata. Private client/CLI pin expected identity and context, bound/canonicalize responses and preserve all cleanup uncertainty. Role delivery/probe/revocation, scope/expiry, malformed responses, parser and actual fixed-tool interoperability are covered by dedicated tests.

Evidence and packaged/live checks are recorded in docs/evidence/scanner-verifier-context-acceptance.json: full source checks, 36 focused controller and 142 client race checks, twelve native private-channel/CLI payloads, six actual scanner attempts and 58 live demo checks passed. This reader does not finish engine operation control, pending-request/lease exclusion, incomplete allocation recovery, cleanup receipts/release or deployed/background worker pairing. Full remaining v4 features and independent H7 release gates remain active.

## Journaled local scanner engine backend (ADR 042)

The explicitly selected operator backend now uses a pinned Moby SDK with an explicit Unix/API transport, durable per-mutation intent/response records, bounded stream handling and crash-persistent uncertainty. A late response cannot rewrite a closed journal. Fsynced hash-linked records and a kernel namespace lock refuse unresolved/torn/unsafe/capacity-exhausted state. The existing-only status command never creates or repairs metadata. Next-exit registration and a later removed-state wait handle fast exit and asynchronous auto-removal.

Evidence: `docs/evidence/scanner-engine-journal-acceptance.json` and the journaled scanner operator guide. Actual six-tool, native CLI, expired-guard and independently observed sandbox fixtures pass with honest stale/unavailable database outcomes. These remain local operator tests: controller gate binding, all-engine-write mediation, verifier lease/allocation exclusion, trusted reconciliation, atomic cleanup release and deployed/background worker pairing remain unfinished. Existing controller cleanup admission stays held. The full remaining v4/H7 requirements remain active.

## Private database snapshots (ADR 043)

The local snapshot command now refuses missing/unrecognized state, opens its source read-only without migration, stages sensitive bytes privately, pins a WAL read snapshot through the existing SQLite driver's online backup API, compacts/checks the isolated output and publishes exclusively with a typed checksum/size receipt. Cancellation, concurrent writes, target races, filesystem hazards and a subprocess storage-write failure are covered. The native compiled command is part of `make test`; the explicit packaged proof is also in hosted demo checks.

Evidence: `docs/evidence/database-snapshot-acceptance.json` records 84 repeated focused checks, eleven native CLI checks, nine packaged checks, two actual receipt schema validations/seven refused variants and 58 live regression checks. Four named demo services use the tested image; the private pre-cutover snapshot is retained. This is controller-state capture only. Gateway/tool bundle capture, authority-safe restore, crash recovery and full GATE-11 restoration/upgrade/disk-full requirements remain unfinished. The rest of v4 and its independent release gates remain active.

## Bound recovery bundles and offline restore (ADR 044)

The current schema-13 reference HTTP demo can now capture and verify a private bundle binding its consistent database, exact persisted gateway configuration, active policy and independently trusted scanner lock. Confirmed restore writes a fresh offline directory, rejects overwrite or bundle-child destinations, and blocks normal startup behind a pending marker until a mandatory audited authority-invalidation transaction and synced completion receipts succeed. Restored sessions, app/scope/worker/verifier authority and queued/running jobs are invalidated; immutable history remains and scanner dispatch cleanup holds persist. The CLI never activates services or claims publisher signatures/application verification.

Evidence: `docs/evidence/recovery-bundle-acceptance.json` links ten native CLI checks, three namespace tests, 72 repeated recovery race checks, actual schema/refusal checks and six same-engine synthetic application checks after disposable database destruction. Full `make test` and controller vet pass. The named demo runs the final image, remains ready and captures/verifies a private bundle through the existing operator init service. An early draft Compose namespace fault, its correction and original-demo readiness repair are documented in ADR 044. The corrected harness validates all effective resource names before startup/cleanup and label-checks the disposable volume before deletion.

This advances GATE-11 only to partial. Second-clean-machine restore, signed release compatibility, automatic atomic installation/reconciliation, incomplete-restore recovery, broad disk-full/update failure coverage and independent acceptance remain unfinished. Other profiles, historical-schema bundle restores, VM execution, independent scanner cleanup release, background worker pairing, offline advisory databases, full investigation/remediation, desktop AI/MCP and remaining H7 gates remain active work.
