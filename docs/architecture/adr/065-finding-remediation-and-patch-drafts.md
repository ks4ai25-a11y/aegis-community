# ADR 065: Finding remediation guidance and validated patch drafts

Status: implemented; unit-tested and validated with a local code model on the bundled synthetic fixture.

## Problem

Static findings told an owner what was wrong but not how to fix it, and manual D8 requires reviewable patch artifacts that never reach production automatically, with path validation and honest priorities.

## Decision

`POST /api/v1/findings/remediation` (owner session only) takes a finding's category, repository, path, line, package data and rule IDs and returns `RemediationV1`: deterministic steps, tests and limitations per category (secrets → revoke first; vulnerable dependencies → upgrade via the package manager; static patterns → rule-specific guidance such as bound SQL parameters). Priorities use the manual's P0–P3 triage, not CVSS.

For static findings, `repository.Excerpt` returns lines around the finding only if the file is listed in the repository's current application map **with the same digest** (so protected, generated and modified files are refused), read inside the asset's `os.Root`. Lines that look like credentials are replaced, and a file containing any is never sent to a model. Secret findings are never excerpted or drafted.

With `draft_patch`, the configured code model (`AEGIS_AI_CODE_MODEL`, default `qwen2.5-coder:3b` in the local overlay) receives the delimited finding and line-numbered file as untrusted data and returns only `{start_line, end_line, replacement_lines, explanation}` under a JSON-schema grammar. Aegis builds the unified diff itself, requires the edit to be within six lines of the finding and at most twelve lines, forbids embedded newlines, applies it to the exact file in memory, and rejects edits that unbalance brackets; one retry receives the rejection reason. A draft is returned with the file digest it applies to and can be downloaded as a `.patch`. Aegis never writes to the repository; drafts are audited.

## Consequences

- Small general models (llama3.2:3b) produced syntactically broken edits that were all rejected; the code model produced a correct parameterised query in about 27 s on CPU.
- The bracket check is a sanity filter, not a parser. Owners must still review and test drafts in their own checkout.

## Validation

`controller/internal/remediate` tests cover exact-diff application, seven unsafe diffs, category guidance, bounded-edit drafts including smuggled newlines and far edits, and bracket balance. Repository tests cover excerpt confinement, other owners, modified files and credential redaction. `tests/integration/remediation_acceptance.py` (`docs/evidence/remediation-acceptance.json`) records guidance, refusals, redaction, a validated draft and an unmodified repository.
