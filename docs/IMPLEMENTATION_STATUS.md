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


## Owner review history and local export (ADR 045)

Owners can now browse and export the complete append-only review chain for an exact owned scan/result/finding. The read-only API rechecks immutable source evidence and every ledger record in one transaction, binds a canonical history digest, refuses gaps/corruption/mismatched scope and returns all at most fifty decisions within the client byte budget. The console validates every record, predecessor, baseline, current head and history digest before showing or locally downloading rationales; stale heads and late reads are refused. Original T0 scanner evidence and cleanup holds stay unchanged.

Evidence: `docs/evidence/finding-history-acceptance.json` records 69 repeated triage/history race checks, actual parser/HTTP payloads, 31 browser checks, six packaged refusal checks, full source tests and controller vet. Four opt-in native engine checks and the live mutation browser journey are explicitly skipped for this increment; the retained demo has no completed scan results, so its packaged proof covers refusal boundaries. New desktop/mobile screenshots were inspected and historical screenshots are preserved by per-run test outputs. No database migration is introduced. Cross-job catalogue/history and review carry-forward, evidence-backed lifecycle transitions, configurable retention, independent engine cleanup/release, deployable workers, advisory databases, VM execution, desktop AI/MCP and remaining H7 requirements stay active.


## Retained finding observations across scans (ADR 046)

The Findings page and owner-only `/api/v1/findings/catalogue` now browse every retained result identity within the current 1,000-job budget, including results hidden behind more than 100 newer jobs. Repository, category, claimed severity and result-time filters bind the cursor alongside owner, page size, ordered roster and inner finding position. Pages revalidate one immutable result and its receipts/reviews, preserve T0 and coverage/error states, distinguish missing-result jobs, and reject changed result sets. UTC-normalized time ranges and actual timestamp ordering cover fractional seconds. Shared finding/review/history controls preserve exact job/result scope, and source links open that scan's inspector.

Local evidence is recorded in `docs/evidence/finding-catalogue-acceptance.json`, including actual parser/HTTP payloads, repeated ownership/time/byte-budget checks, full source tests, console browser regressions and named-demo API/browser checks. No database migration or new controller engine/policy mount is introduced. This is a retained-observation catalogue, not a completed cross-revision canonical finding graph or global vulnerability total. Cross-snapshot equivalence, proof/remediation lifecycle, broader retention and application registration, worker deployment/cleanup release, advisory databases, VM execution, desktop AI/MCP and remaining H7 release gates remain unfinished.


## Packaged journaled worker and SDK-only preflight (ADR 047)

A separate opt-in Compose profile now packages the trusted one-shot static scanner worker, both guards, fixed rules and tool lock without a Docker CLI. Explicit Unix endpoints use a read-only SDK metadata client with fixed API 1.55, exact GET paths, strict bounded complete JSON and immutable local image/platform checks. There is no pull or CLI fallback. The deployed worker is UID 10001, network-none, read-only and cap-drop; it receives a private enrollment volume/socket, approved read-only assets and a canonical daemon-host workspace mirror. Child tools receive neither engine socket nor enrollment credentials.

Actual local ARM64 execution covers all six preloaded pinned tools and six committed receipts. Missing databases remain tool errors. Owner findings stay T0 and a later queued job remains held behind `cleanup_required` even with six settled local journal attempts and observed child absence. The isolated harness verifies its own resource removal and preserves uncertainty. Source tests and repeated metadata race/fault tests pass. A separate disposable Linux AMD64 CI job passes actual packaged Bandit execution and the held-next-job/resource-cleanup assertions using a checksum-pinned API-compatible engine; source/browser and trusted-demo/recovery jobs pass at the same implementation commit. Archive extraction is bounded and refuses unsafe members. These pins do not establish publisher signatures.

See `docs/evidence/cli-free-worker-acceptance.json`, `docs/evidence/packaged-worker-acceptance.json`, ADR 047 and the packaged worker operator guide. This is trusted operator deployment, not controller-independent all-engine-write mediation or cleanup release. Background provisioning/recovery, authoritative cleanup, advisory databases, cross-revision proof/remediation, VM-backed execution, desktop AI/MCP, independent installs/signatures/review and remaining H7 gates remain unfinished. The overall v4 goal remains active and public beta remains NO-GO.


## Immutable operator engine scope (ADR 048)

The reference packaged worker now requires an immutable local operator binding for its engine and canonical workspace registry. Missing/changed/unavailable scope refuses before claim or source allocation. The controller independently constrains configured workspace reservations and launches, including older clients, and exposes only an authenticated private read. Initial provisioning requires an owned repository and no active/held dispatch; exact repeats preserve identity, and replacement/reset is unavailable. Restore removes prior host binding while retaining history and cleanup holds. No database migration is added. Legacy unconfigured native experiments remain explicitly unbound.

Local evidence in `docs/evidence/engine-binding-acceptance.json` and `docs/evidence/engine-bound-worker-acceptance.json` covers repeated race/fault checks, source tests/vet, actual schemas and ten packaged checks with all six tools. Findings stay T0, unavailable databases stay errors, and a second job stays held. Journal namespace binding, independent all-write mediation, trusted reconciliation and cleanup release remain unfinished, alongside VM execution, advisory databases, proof/remediation lifecycle, AI/MCP and remaining H7 requirements.


## Controller-bound engine journal namespace (ADR 049)

The packaged worker now requires a separate immutable journal root/UID and namespace approval bound to the existing engine approval. Missing, substituted, busy or unresolved state refuses before claim. The executor reopens only existing journal state and checks approval under its lifetime lock before a mutation intent, preventing a fresh namespace from inheriting authority. New launch revision 1.2 preserves the binding and namespace hashes and rejects configured-scope downgrade. Historical guarded records remain readable with conservative flags. Restore invalidates both host bindings while retaining history and cleanup holds. No migration or browser mutation endpoint is added.

Evidence in `docs/evidence/journal-binding-acceptance.json` and `docs/evidence/journal-bound-worker-acceptance.json` covers existing-only/fault/concurrency/authority tests, actual packaged substitution and no-repair checks, all six tools, full source checks and typed schemas. This advances journal/gate metadata binding; it does not complete exclusive all-write mediation, independent workspace/lease and late-start exclusion, trusted reconciliation or cleanup release. The broader v4 objective, VM isolation, advisory databases, proof/remediation, AI/MCP and remaining H7 release gates remain active.


## Selected broker and limited dispatch client (ADR 050)

A dedicated broker now owns scanner authority and the bound worker execution path. Its separate scratch dispatch client mounts only a limited credential and private broker socket, with no engine group/socket, controller enrollment/channel/database, source or journal. The finite protocol accepts an empty object only and returns state/digests/counts with conservative false cleanup/all-write flags. The controller immutably selects one enrolled broker before claims/live execution; other workers are refused without consuming admission. Role capabilities must differ, and shutdown retains its process lock until cancelled work joins. Restore removes the binding and revokes enrollment while preserving history/holds. No migration or browser provisioning endpoint is added.

This advances privilege separation for scan coordination. Exclusive daemon mediation, independent verifier/reconciliation, allocation/lease and late-start exclusion, atomic cleanup release, safe enrollment replacement, VM execution, advisory databases, proof/remediation, desktop AI/MCP and remaining H7 gates remain unfinished.

Evidence: `docs/evidence/scanner-broker-acceptance.json` and `docs/evidence/broker-dispatch-acceptance.json` record the final six-tool broker/client run, sixteen checks, fourteen one-shot regressions, source tests/vet and minimal-client dependency/schema checks. Neither fixture releases cleanup admission or promotes scanner proof.

## Isolated engine authorization adapter (ADR 051)

A separate opt-in native Docker authorization plugin now restricts verified TLS broker/observer principals to the shared fixed static scanner profile and exact tracked container lifecycle. A plugin-owned durable journal records intents before allow and quarantines unresolved mutation responses across restart. The disposable Linux CI fixture passes thirteen checks on an additional TLS-only daemon for real guarded Bandit, policy refusals, native gRPC exclusion, fail-closed plugin failure and its settled separate journal; it does not reconfigure the workstation or retained demo. Packaged broker TLS integration, authenticated controller leases, independent source/guard attestation, exclusive engine deployment, cleanup reconciliation and release remain unfinished. All mediation/release authority flags remain false; full v4 and public beta remain NO-GO.

## Selected broker TLS transport (ADR 052)

An additional disabled profile connects the selected packaged broker to the restricted daemon through end-to-end TLS over a credential-free private Unix relay. The broker receives no raw engine socket or supplemental daemon group; the limited dispatcher still receives no engine credential. Public CA/client certificate identity is included in immutable engine binding and reread before each cooperating SDK RPC, including reused connections. TLS mode uses explicit tracked removal, refuses plaintext/CLI fallback and retains cleanup holds. Controller-authenticated plugin leases, independent source/guard verification, approved certificate recovery/rotation, independent reconciliation/release and full v4/H7 acceptance remain unfinished. Public beta remains NO-GO.

## Fresh controller launch observations (ADR 053)

The private observer channel now supports a challenge-bound read of an exact revision 1.2 launch under the current engine/journal/broker chain and live job/worker lease. The client validates nested scope, challenge, freshness and expiry without receiving or renewing a lease. Current revision 1.2 cleanup-context reads and TLS preflight schema parity are corrected. This is a read-only precondition: the daemon plugin does not consume it yet, and durable allocation authorization, independent byte checks and cleanup release remain unfinished. Public beta remains NO-GO.


## Controller-observed native daemon preconditions (ADR 054)

The opt-in native `serve-bound` authorizer now checks fresh private controller observations before and after source/guard verification at each create/start. It requires the current revision 1.2 launch and full immutable engine/journal/broker chain, exact tool/image/version/lock, original duration/deadline, native guard architecture, reserved workspace and complete source snapshot. Semgrep needs an additional operator-pinned rules snapshot. Changed bytes, stale/revoked/cancelled scope, controller/capability loss and cancelled requests deny execution; exact tracked removal remains available. A synced local journal seal prevents configuration substitution or downgrade, and attempts retain its digest. No lease renewal, controller migration or cleanup release is added.

Real private-channel/SQLite integration tests exercise plugin decisions using synthetic Docker envelopes and guard bytes, alongside seal/restart/fault and existing sandbox-observer regressions. The current packaged TLS acceptance fixture remains in the earlier unbound mode: bound packaging and actual bound-daemon execution still need implementation and verification. Controller allocation fencing, independent reconciliation/release, VM isolation, advisory databases, proof/remediation, desktop AI/MCP and remaining H7 requirements remain unfinished. Full v4 stays active and public beta remains NO-GO.


## Separate packaged controller-observed authorizer (ADR 055)

An additional scratch image and disabled Compose profile package the native bound gate with a separate read-only observer channel/capability, read-only canonical source registry and exclusive plugin journal/socket. It has no engine socket/group/client identity, broker/dispatch credential, controller database or network. The new disposable Linux CI journey retains the previous raw/broker/TLS regressions and requires actual guarded execution behind this separate container, unregistered-profile refusal before mutation, failure on authorizer loss, sealed-journal downgrade refusal and a held second job. Runtime payloads stay private; public checks report test statuses.

This does not add controller allocation fencing or independent cleanup/release. Actual daemon race/fault coverage, exclusive host provisioning/recovery, VM execution, advisory databases, proof/remediation, desktop AI/MCP and remaining H7 requirements remain active. Public beta remains NO-GO.

## Scanner authorizer enrollment foundation (ADR 057, partial)

Schema 14 adds a distinct operator-enrolled authorizer identity bound to owner, engine, registry and intended policy, with private credential delivery, expiry, immutable scope and retained revocation. The private Unix API exposes identity only. Worker/observer/authorizer roles remain separate; no admit, completion, reset or cleanup-release operation exists yet. Native synthetic CLI and role/channel tests cover delivery, refusal, scope and audit behavior. Migration/restore tests preserve old checksums and holds, revoke restored authorizers, and retain verified version-13 bundle compatibility. Snapshot history validation now reads one row beyond supported versions, closing the fixed-row-limit gap exposed by migration 14. See [operator instructions](operators/scanner-authorizers.md).

Durable mutation admission, late-start fencing, independent engine reconciliation, confirmed cleanup release, usable repeated scans, journal recovery/retention and advisory-database provisioning remain required. Enrollment alone is not proof of any of these. Full v4/public beta remains NO-GO.

## Defence plane: multi-site, detectors, assessment, proposals and MCP (ADRs 056, 058–061)

**Multi-site gateway (ADR 056).** Policy schema 1.1 adds owner-registered sites behind one gateway revision, each with its own host names, private origin, mode, CRS settings and exclusions; schema 1.0 documents keep their digests. Validation refuses loopback/metadata/Aegis-service origins, duplicate or demo host names and unsafe exclusions, and Protect is refused for a site the parent revision did not observe. Registered sites' gateway-assigned request IDs carry the site ID, so events and incidents are attributed without trusting client headers. The console has a Sites page and a site selector. `docs/evidence/multi-site-acceptance.json` records 13 live checks on an isolated local stack. TLS termination and per-site rate limits remain open.

**Deterministic detectors (ADR 058).** DET-01…06 (CRS match, path enumeration, brute-force candidate, request burst, 5xx spike, sensitive route) run on persisted access events with explicit, versioned thresholds, bounded state and a reported eviction counter, using daily-rotating in-memory HMAC pseudonyms of client address and path. Every detector records only; none blocks. `docs/evidence/detector-acceptance.json` records a live DET-02 incident with pseudonymous evidence. DET-07 (policy regression) and DET-08 (origin drift) remain open.

**Advisory assessment (ADR 059).** Each incident has a deterministic `IncidentAssessmentV1` with no model, network or account, and optionally one from an owner-run local model (Ollama overlay or any OpenAI-compatible server). The model sees a compact, delimited, sanitized dossier, is constrained by a JSON-schema output grammar, and its reply is validated (unknown evidence references, enums, control characters and oversized text removed) with deterministic fallback. Assessments are audited. `docs/evidence/ai-assessment-acceptance.json` records a llama3.2:3b assessment in about 40 s on CPU.

**Mitigation proposals (ADR 060).** The sanitizer keeps the matched argument name only. CRS incidents produce complete candidate revisions (parameter-scoped exclusion, Protect) that must pass the pinned validator, the isolated fixture preview and explicit approval. The live run shows the fixture rejecting an exclusion that would remove the bundled negative control, and no proposal activating itself. Code-patch proposals for source findings remain open.

**Assistant connections (ADR 061).** Migration 015 adds read-only connector credentials (hash only, immutable scope, one-way revocation, revoked on restore). Bearer requests are restricted to an explicit GET allowlist before routing. `aegis-mcp` is a local stdio MCP server with seven read-only tools for desktop AI apps. `docs/evidence/mcp-acceptance.json` drives the real binary. GUI compatibility in each desktop app is not yet tested.

**Exposure comparison (E3).** `/sites/{id}/exposure?repository_id=` classifies declared repository routes against observed templates as `both`, `declared_only`, `observed_only` or `unclassified`, shown on the Endpoints page.

These increments complete large parts of the Community defence plane (E3–E7, F6, F7) but not the remaining H7 release gates. Public beta remains NO-GO.

## Workspace registry identity and close barriers (ADR 057 prerequisite)

Fresh-only native registry provisioning adds a private protocol-2.0 namespace bound to original path/UID/device/inode and a fresh nonce. Read-only existing-state barriers require the approved namespace and retain the global kernel lock through a synchronous callback. Creation acknowledgement and new Close operations share that lock; Close positively releases the lifecycle lease before confined workspace deletion and sync. Substitution, corrupt or missing metadata, active/pending creation and uncertain closure retain/refuse unknown state. Native CLI, race/fault and actual pre-barrier compatibility checks cover the filesystem component; the packaged controller-authorizer fixture now uses explicit namespace provisioning. See [operator instructions](operators/workspace-registry-barriers.md).

The controller still does not admit/complete mutations or release cleanup. Original-engine reconciliation, role separation for release, protocol binding, actual late-allocation race coverage and migration 016 remain required. Full v4 and public beta remain NO-GO.

## HTTPS, rate limits, trusted proxies, canary, expiry and adapters (ADRs 062–064)

Registered sites can use a free ACME certificate or an Aegis-local CA, with explicit HTTPS redirects and unprivileged 8080/8443 listeners (`deploy/compose.public.yaml` publishes 80/443). Approved per-client rate limits (pinned `caddy-ratelimit`) return 429 before the WAF and origin, and owner-listed trusted proxy ranges supply the client address behind a CDN; untrusted `X-Forwarded-For` is ignored (real-gateway tests). DET-07 is a live canary that probes the gateway with the bundled synthetic controls after every activation and every 15 minutes and opens an urgent incident on regression or revision drift. Exclusions may expire; the controller activates the stricter revision only after it passes the isolated fixture (validated live). `policy.Adapter` defines the enforcement-point contract with capability manifest at `/api/v1/adapters`. `scripts/quickstart.sh` and `docs/user/getting-started.md` give a one-command start; the quickstart was syntax-checked but not run end to end against a fresh machine. Browser specs cover sites, incident assessment/proposals and connectors (58 pass, 2 live skipped with system Chrome).

Still open in the defence plane: code-patch proposals for source findings, DET-08 origin drift, independent installation and GUI tests in each desktop AI app. Release gates other than evidence additions are unchanged; public beta remains NO-GO.

## Remediation, signed evidence, diagnostics, capacity and negative tests (ADRs 065–067)

Static findings now have deterministic remediation guidance, and code findings can get a local-model patch draft that Aegis builds from a bounded line edit and only returns if it applies to the exact inventoried file with balanced brackets; credential-like lines are redacted and such files never reach a model (ADR 065). Verification reports can be exported with an installation Ed25519 signature and verified offline with `aegisctl report verify` (ADR 066). `aegisctl diagnostics` produces a read-only, counts-only support bundle. The gateway benchmark measured added p95 of 2.5–9.3 ms for short and ~1 KiB requests up to 100/50 RPS and found that large single-field bodies cost ~7 ms of CPU per KiB; sites can now cap bodies (`max_body_kib`), and policy changes no longer freeze when the gateway is saturated (ADR 067). `tests/negative-security/defence_negative.py` runs 12 abuse checks against a live stack. All defence-plane acceptance evidence was refreshed from a clean committed build.

Open on the defence side: DET-08 origin drift, independent installation and GUI tests in each desktop AI app. Scanner cleanup/release (migration 016, ADR 057) is in progress by the scanner workstream. Public beta remains NO-GO.
