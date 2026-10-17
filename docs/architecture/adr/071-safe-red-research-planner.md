# ADR 071: Safe red research planner

Status: implemented (controller, API, console); plans only. Execution stays with the existing research queue and the operator lab CLI.

## Problem

D5 asks for an AI red research agent that turns inventory and findings into testable hypotheses without becoming an unbounded attacker.

## Decision

`controller/internal/redteam` is an investigation planner.

- **Inputs:** the owner's application map, the latest retained normalised findings (secret candidates are never shown to a model) and redacted source excerpts through `repository.Excerpt`. Files that look like they hold credentials are withheld.
- **Deterministic planner (always runs):** a GET route on a resource path with an identifier and no authentication-named middleware → `cross_tenant_read_fixture_v1` (`tenant_isolation_01`). A static SQL construction finding → `waf_sqli_fixture_v1` (`waf_blocks_sqli_pattern_01`). At most five.
- **Optional model round:** one JSON-schema-constrained call over delimited facts. It may request up to three `read_redacted_source_excerpt` reads for one more round. Tool names outside `list_routes`, `read_redacted_source_excerpt`, `find_related_findings` and `propose_test_template` are rejected. So are templates outside the catalogue, claims naming URLs or IP addresses, and references to files outside the inventory. Every rejection is reported. At most three model hypotheses are kept, and the deterministic plans survive any model failure.
- **Output:** `ResearchPlanV1`-shaped plans (D5.1), always `hypothesis_unverified`. Each has the template's runner and next step: the owner-approved research queue for the WAF fixture, or the operator lab CLI for the tenant fixture, which has no controller runner. There is no tool that runs commands, contacts hosts, writes files or creates credentials.
- **Access:** `POST /api/v1/repos/{id}/research-plan {"use_model": bool}` runs as an advisory model call: one at a time, outside the global mutation lock, audited as `research.plan`. The console has **Research plan** on the repository map.

## Limitations

The templates test bundled synthetic fixtures, not the owner's running application. Hypotheses come from static inventory and tool claims. The tenant template runs only on the operator host.

## Validation

Unit tests cover deterministic plans and stable identities, a hostile scripted model (uncatalogued tools, path traversal, credential-file excerpt, URL claim, `deploy_to_prod`, out-of-inventory references), and fallback on model failure. API and browser tests cover the console flow. The live run (`docs/evidence/ai-eval-planner-live.json`) uses a real local model with an instruction planted in a source excerpt.
