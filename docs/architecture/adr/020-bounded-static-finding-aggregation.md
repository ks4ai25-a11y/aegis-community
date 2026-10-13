# ADR 020: Bounded static finding aggregation

Status: implemented in parser 1.2; source and pinned fixture checks recorded separately. Durable finding storage and full v4 D4 canonicalization remain unfinished.

The parser now aggregates its normalized findings before returning a result. Every newly normalized provenance source retains its own normalized severity claim. Aggregation selects the highest supplied severity for presentation, while status remains suspected, confidence low and evidence tier T0. Agreement between tools does not establish exploitability, context validation or independent review.

Dependency claims with the same application, repository, PURL, installed version, single advisory and lockfile path share a canonical ID across tools. The grouping key additionally binds the input snapshot digest. Different snapshots never merge. Static and secret claims retain their tool and rule namespaces; equal rule text across unrelated tools cannot establish AST-region equivalence. Parser 1.2 changes these identities intentionally. Historical receipts are not rewritten, and consumers must retain parser and snapshot identity when comparing versions.

Every original provenance entry is retained, including repeated entries. Aggregation clones source/advisory slices so it cannot mutate earlier in-memory receipts. A finding has at most sixteen provenance entries, matching the schema. A seventeenth entry refuses the whole parse as tool_error rather than silently dropping evidence or returning completed zero findings. The current cap is an explicit resource limit; durable storage will need separate immutable source records for larger evidence sets.

Source severity_claimed is optional for historical compatibility. Parser versions 1.0 and 1.1 remain accepted; absence of a historical source severity does not invent one. New executor receipts and provenance use parser 1.2. This helper accepts internal normalized findings; it is not a general-purpose untrusted FindingV1 import validator.

Tests cover cross-tool dependency identity independent of input order, source severity disagreements without proof promotion, snapshot and static namespace separation, non-mutation of earlier receipts, source overflow reaching the real parser error path, and refusal of proof-tier or mixed-input aggregation. Actual pinned scanner acceptance validates the updated generated schemas and input/tool receipt binding.

Full AST-region normalization, ecosystem-complete PURLs, advisory alias/range equivalence, persistent append-only finding history, multi-scanner durable jobs and investigation views remain required. This increment does not complete those requirements or any independent release gate.
