# Community → Frontier transition plan

Status: planning document. Community remains independently useful and is never weakened to sell Frontier. Frontier is a separate, private codebase that **consumes** Community through stable seams. Specifications: `Aegis_Community_OSS_First_Engineering_Master_Manual_v4.md` (Community) and `Aegis_Frontier_Enterprise_Engineering_Master_Manual_v3.md` (Frontier).

## 1. The product boundary in one sentence

Community protects and verifies **one installation's HTTP perimeter** with local evidence. Frontier adds **owner-confirmed application semantics** (who may do what to which object), enforces them at **authoritative points** (app middleware, database, identity), proves the outcome in **disposable replicas**, and keeps that proof **fresh across changes**, for many applications and teams.

Anything that is "Community plus a bigger model, more rules or a nicer dashboard" is not Frontier.

## 2. What Frontier reuses unchanged

| Community component | Path | Frontier use |
| --- | --- | --- |
| Typed policy model, validator, renderer | `controller/internal/policy`, `controller/internal/domain` | Edge enforcement adapter. Frontier's placement planner emits `PolicyRevisionV2` documents for the HTTP layer only. |
| Privileged deployer boundary | `controller/cmd/policy-deployer` | Template for every Frontier enforcement adapter: typed request in, compare-and-swap revision, definitive busy/unknown states. |
| Gateway + sanitizer | `gateway/` | Frontier's local edge sensor. Pseudonymous `client_key`/`path_key` already support cross-signal correlation without raw identifiers. |
| Telemetry ingest + detectors | `controller/internal/ingest`, `controller/internal/detect` | Frontier Blue Fusion consumes `SecurityEventV1` and detector incidents as one sensor class (WAF) among several. |
| Scanner execution, receipts, findings | `alpha/`, `shared/source/scanevidence`, `controller/internal/scanqueue` | Frontier research workers reuse fixed-argv, pinned-image, receipt-ledger execution as their tool sandbox. |
| Scope grants, research queue, verification reports | `controller/internal/{scope,research,verify}` | Seed of Frontier `ResearchPermit` and `VerificationAttestation`. |
| Audit chain, snapshots, recovery bundles | `controller/internal/store`, `controller/internal/recovery` | Customer-hosted Frontier reuses them; managed Frontier replaces storage but keeps the evidence semantics. |
| Contracts and generators | `contracts/`, `scripts/generate_*.py` | Single schema source; Frontier adds its own schemas in its repo and imports Community's. |

## 3. Seams Community must keep stable (the "Frontier contract")

These are versioned interfaces. Breaking one requires a new major schema version and an ADR in Community.

1. **`PolicyRevisionV1/V2`** — one revision governs every site; `sites[]` entries are additive. Frontier never writes Caddy syntax directly.
2. **`SecurityEventV1`** — fields `site_id`, `request_id` (site-prefixed), `client_key`, `path_key`, `rule_ids`, `decision`, `gateway_revision`. Frontier correlates on `request_id` and pseudonyms.
3. **Detector incidents** — `detector_id`, `detector_version`, knobs and evidence references in the incident record. Frontier treats each as a typed signal, never as ground truth.
4. **Verification report** (`VerificationReportV1`) — baseline/candidate digests, fixture digest, claim level. Frontier's `VerificationAttestation` wraps it and adds a signature.
5. **Scanner receipts and findings** (`ScannerSuiteResultV1`, `FindingV1`) — immutable, owner-bound. Frontier's graph ingests them as `GraphFact` with provenance.
6. **Deployer protocol** — `status/validate/apply`, `expected_revision`, `429 = nothing attempted`, `503 = unknown`. Every Frontier enforcement adapter implements the same three verbs and the same three outcome classes.
7. **Local API v1** under `/api/v1` with generated clients. Frontier's connector talks to a Community installation only through this API and a scoped connector credential (to be added; see §6 step C2).

## 4. Repository and licensing layout

```text
aegis-community/            public (current repository)
  … unchanged layout …
aegis-frontier/             private
  go.mod                    requires aegis-community modules by tag
  connector/                runs beside a Community install; scoped API client; signed uploads
  graph/                    Security Semantics Graph (PostgreSQL, bitemporal facts)
  invariants/               DSL parser, type checker, placement planner, compiler
  adapters/                 postgres-rls, node-middleware, opa, caddy (wraps Community policy)
  twin/                     disposable replica builder (Compose/K8s), research permits
  research/                 red research planner + independent verifier
  fusion/                   Blue multi-signal correlation
  remediation/              candidate generation, CI gate, canary/rollback orchestration
  assurance/                stale-proof DAG, evidence ledger (Sigstore/KMS)
  platform/                 tenancy, SSO/SCIM, billing/metering, regions
  console/                  enterprise UI (reuses Community design tokens)
```

Rules:

- Community never imports Frontier. CI in Community fails if any `aegis-frontier` import appears.
- Frontier pins Community by release tag and runs Community's own test suite against that tag in its CI.
- If Community moves from Apache-2.0 to a source-available licence (BUSL/FSL), do it **before** outside contributions arrive, and add a CLA. Frontier stays proprietary. Third-party notices remain per component.

## 5. Phased plan with exit evidence

Each phase is gated by evidence, not dates. Phases map to Frontier milestones FX0–FX8.

### Phase F0 — Contracts and seams (Community work, now; connector credential done)

- Freeze the seven contracts in §3; publish them as JSON Schema with generated Go/TS/Python bindings (partly done).
- Add a **connector credential** to Community: owner-issued, scoped (read events/incidents/findings/policy; propose-only), expiring, revocable, audited. No write access to policy activation.
- Add an **adapter interface** (`status/validate/apply` + capability manifest) and refactor the Caddy deployer to be its first implementation.
- Exit: Community tests prove a connector token cannot activate policy, read another owner's data, or outlive revocation.

### Phase F1 — Meaning (Frontier FX1)

- Frontier `graph/`: ingest Community events, application maps, findings and policy revisions as provenance-tagged facts (`observed`, `inferred`, `owner_confirmed`, `verified`).
- Owner confirms `resource_owner == acting_tenant` for one reference app (Next.js + PostgreSQL, two tenants).
- Exit: query "which actions can tenant A perform on object B, established by which code and enforcement point" returns a graph slice with gaps and freshness; mutating one grant changes the answer.

### Phase F2 — Twin (FX2)

- Build a disposable replica of the reference app with synthetic tenants from repository + schema; reuse Community's scanner sandbox profile for egress-free execution.
- Exit: a previously unseen cross-tenant read regression is reproduced in the twin with no production contact; cleanup is verified.

### Phase F3 — Outcome integrity (FX3)

- DSL v1 supports one class: tenant ownership. Compile to PostgreSQL RLS **and** Node middleware; refuse unsupported placements with `422_UNSUPPORTED_SEMANTICS`.
- Exit: cross-tenant read denied on REST and async export paths; same-tenant reads succeed; edge-only "fixes" are rejected.

### Phase F4 — Verified repair (FX4/FX5)

- Two candidate fixes (RLS policy vs middleware patch), independent verifier, approval bound to the artifact digest, PR via the customer's CI, canary with rollback.
- Exit: one deliberately bad candidate is rejected; duplicate deploy messages are harmless; approval revocation is enforced.

### Phase F5 — Continuous assurance (FX6)

- Proof records depend on code/schema/policy digests; a change invalidates them and schedules retest; CI gate blocks promotion of a regressing commit.
- Exit: a regression commit is blocked before release, and the UI shows the proof as `STALE` until re-verified.

### Phase F6 — Pilot readiness (FX7)

- Customer-hosted and private-data-plane installs, SSO, regional keys, backup/restore, external security assessment, two independent pilot installs without engineering help.

### Phase F7 — Commercial proof (FX8)

- Published head-to-head benchmark against Community on the same multi-service fixture (Frontier manual §M). Features without measured differential value are removed.

## 6. Concrete Community work that makes the transition easy

Ordered by value; each item is useful to Community users on its own.

| Step | Work | Why it helps Frontier |
| --- | --- | --- |
| C1 | Multi-site gateway policy (**done**, ADR 056) | Frontier protects many apps per install from day one. |
| C2 | Scoped connector credential + read-only export API (**done**, ADR 061) | The only channel Frontier needs into a Community install. |
| C3 | Enforcement adapter interface around the deployer (**done**: `controller/internal/policy/adapter.go`, `/api/v1/adapters`) | Frontier adds RLS/middleware/OPA adapters behind the same verbs. |
| C4 | Deterministic detector catalogue (**DET-01…07 done**, ADRs 058, 063) | Typed signals for Frontier fusion. |
| C5 | Local-model AI investigator producing `IncidentAssessmentV1` (**done**, ADR 059) | Same envelope Frontier's managed investigators emit; Community stays zero-cost via local models. |
| C6 | Remediation proposal records (`MitigationProposalV1`) (**done**: WAF/rate-limit proposals ADR 060, validated code-patch drafts ADR 065) | Frontier's remediation transactions extend, not replace, them. |
| C7 | Signed evidence export (detached signature over report digest, local key) (**done**, ADR 066) | Frontier's evidence ledger verifies Community-originated proofs. |
| C8 | Application map ↔ observed route diff (E3) (**done**) | First "meaning" facts for the graph. |

## 7. What stays exclusive to Frontier

Graph, invariant compiler, authoritative adapters beyond the HTTP edge, twins of customer applications, multi-agent research, cross-layer fusion, remediation transactions with canaries, stale-proof assurance, multi-tenant platform, SSO/SCIM, regional residency, managed operations and SLAs. Community keeps every security fix, rule update and local verification capability.

## 8. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Community API churn breaks Frontier | Contracts in §3 are versioned; Frontier CI runs against pinned Community tags. |
| Frontier logic leaks into Community | Import ban in Community CI; separate repositories; code review rule. |
| Customers resist authoritative adapters in their code/DB | Start with dry-run diffs and PRs into the customer's own CI; never write production schema directly. |
| Twins are unfaithful | Restrict to the reference stack first; report coverage and divergence explicitly. |
| Scope explosion | Ship F0–F3 for one stack and one invariant class before any enterprise platform work. |
| Licence change backlash | Decide before external contributions; keep a generous self-hosting grant. |
