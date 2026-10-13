# ADR 018: Hostile scanner JSON and dependency identities

Status: implemented; real pinned-tool fixture compatibility passed; independent review and the full release gates remain required.

Scanner JSON is untrusted input. Go's default struct decoder accepts repeated and case-equivalent field names. Before typed parsing, the adapter now checks UTF-8, a single document, object-key uniqueness including escaped/case-folded names, depth 64, 250,000 tokens, 10,000 entries per object/array, 1 MiB strings and the existing 8 MiB total output bound. Malformed or ambiguous output yields tool_error with no findings, never a completed zero-finding result. Missing/null Trivy result arrays are also rejected. Raw snippets, advisory details, numeric scores and secret matches are not exported by normalization.

Dependency IDs previously omitted package and installed version when assigning an advisory at the same lockfile path. Distinct packages could share an ID. Parser version 1.1 now hashes length-separated JSON identity fields including owner/application boundary, repository, category, advisory, lockfile, package URL, declared package name and installed version. Deduplication retains separate applications, repositories, lockfiles, versions and categories. No cross-advisory alias merge is implemented without affected-range evidence.

FindingV1 adds optional package_name so unsupported OSV ecosystems retain their declared identity without fabricating a package-url type. npm and PyPI mappings follow the upstream Package URL type definitions, including encoded npm scope and version components. Other ecosystems currently omit derived PURL; complete ecosystem support remains required. Existing scanner-supplied PURLs receive bounded structural screening, not full conformance certification. Package and version controls/format characters are rejected. Secret values remain omitted; a redacted Gitleaks placeholder does not produce a fake secret fingerprint.

Configuration findings require explicit ConfigReview consent in the adapter job. The standard operator executor does not enable that flag and still runs Trivy with its vulnerability-only profile. A standalone parser flag is not an owner-authorized durable configuration-review API; that capability remains unfinished.

Sources: https://github.com/package-url/purl-spec/blob/main/types/npm-definition.json and https://github.com/package-url/purl-spec/blob/main/types/pypi-definition.json. OSV ecosystem identity is described at https://ossf.github.io/osv-schema/ .

Tests cover duplicate/case/escaped keys, invalid UTF-8, trailing documents, depth/array limits, missing results, distinct package/version IDs, owner/repository/lockfile separation, malformed coordinates, forged score non-elevation, private-detail omission, redacted-secret handling and explicit configuration consent. These changes do not claim full rule coverage, exploit confirmation, complete SBOMs, advisory authenticity or durable scan scheduling.

The full `make test` checks passed. All ten pinned tool fixtures passed their expected completed/tool_error outcomes and current receipt schema. A 20-second, two-worker fuzz run exercised 123,090 inputs across six parsers without a failure; this is bounded local fuzz evidence, not exhaustive validation. Parser 1.0 receipts remain schema-compatible alongside parser 1.1.
