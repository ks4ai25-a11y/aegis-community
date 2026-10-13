# ADR 019: Pinned Bandit static Python adapter

Status: implemented; local pinned fixture acceptance passed. Independent signature, distribution-notice and isolation review remain release requirements.

The v4 manual requires a Bandit adapter alongside the other OSS tools. The official image publishing workflow tags `latest`, not individual releases. A version-tag fetch failed; we inspected the live OCI index, selected immutable digest `sha256:e4719e136e3a4fa8d19cfb0e58e292b253d3202b4a32e7433c98df963391210e`, fetched that digest and ran a bounded, non-root, network-disabled version probe without source mounts. It reported Bandit 1.9.4 and Python 3.12.15. Runtime execution uses only the digest, never a mutable tag or automatic pull.

The finite scanner guard now admits Bandit with fixed argv `--ini /dev/null --ignore-nosec -r /src -f json`. The empty INI path prevents repository `.bandit` flags from altering targets, output paths, profiles or exclusions. Inline nosec comments cannot silently suppress findings in this default profile. Built-in plugins come from the pinned image, whose work directory is /bandit; the source snapshot at /src is never the Python execution directory or an imported module. Only read-only AST analysis is authorized. Repository scripts and dependency installation remain unavailable.

Exit 1 is a valid findings result, distinct from a tool failure. Parsed errors produce completed_partial and a sanitized SCAN_PARTIAL diagnostic, never clean completion. Raw source snippets, error details and issue text are omitted. Findings remain suspected T0 static claims. There is no exploitability, code-fix or complete Python coverage claim.

ScannerExecutionV1 now has an optional parser_version property for historical schema compatibility. Every new executor receipt populates it, including zero-findings, partial and tool_error runs; finding provenance uses the same version constant. Historical receipts remain valid when they lack this newly introduced field.

Acceptance covers seeded and safe Python alongside all six pinned tools, repository INI and nosec suppression attempts, a top-level exception canary that must not execute or escape normalization, and malformed Python that must disclose partial coverage. These are trusted inert fixtures, not independent hostile-code isolation certification. The same guarded input validation, network-none profile, limits, cleanup and admission rules apply.

Bandit source is Apache-2.0, but complete image/transitive notices and publisher signature validation remain pending. The upstream workflow and versioned source are documented here, not assumed to establish verified publisher identity:

- https://github.com/PyCQA/bandit/blob/1.9.4/.github/workflows/build-publish-image.yml
- https://github.com/PyCQA/bandit/blob/1.9.4/bandit/cli/main.py
- https://github.com/PyCQA/bandit/blob/1.9.4/LICENSE

Evidence: docs/evidence/bandit-acceptance.json and docs/evidence/snapshot-scanner-acceptance.json. Durable controller scanner orchestration, additional rule coverage and all open release gates remain unfinished.
