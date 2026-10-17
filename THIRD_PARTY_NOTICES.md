# Third-party component inventory

Aegis-authored source is Apache-2.0. This file is an inventory under review, not a completed legal approval or substitute for upstream licence/notice text. Container distributions include additional OS and transitive dependencies; `scripts/release/release_evidence.py` produces their SBOMs and licence texts for each release.

| Component | Pinned source | Distribution/use | Review state |
|---|---|---|---|
| Caddy | gateway/go.mod and go.sum, v2.11.4 | Gateway binary | Licence texts bundled per release; legal review pending |
| coraza-caddy | gateway/go.mod and go.sum, v2.6.2 | Linked gateway module | Licence texts bundled per release; legal review pending |
| caddy-ratelimit | gateway/go.mod and go.sum, v0.1.1-0.20260612195517-5625512f24f6 | Linked gateway module (per-site rate limits) | Apache-2.0; licence text bundled per release |
| Coraza / OWASP CRS | gateway/go.sum, v3.8.1 / v4.25.0 | Engine / embedded rules | Licence texts bundled per release; legal review pending |
| modernc SQLite, crypto and UUID | controller/go.mod and go.sum | Controller binary | Licence texts bundled per release; legal review pending |
| React, Vite, TypeScript, Lucide | console/package-lock.json | Browser assets / build tools | Licence texts bundled per release; legal review pending |
| Playwright Test 1.64.0 and its pinned test browser | console/package-lock.json; console/playwright.config.ts | Development/CI browser tests; not an Aegis runtime worker | Full browser/transitive licence and licence text bundled per release |
| Semgrep CE | tools/scanners.lock.json | Optional standalone scanner image | CLI/engine licence separation requires review |
| OSV Scanner V2, Trivy, Syft, Gitleaks | tools/scanners.lock.json | Optional standalone scanner images | Licences, notices and publisher signature review pending |
| Bandit 1.9.4 | tools/scanners.lock.json; https://github.com/PyCQA/bandit/blob/1.9.4/LICENSE | Optional standalone upstream scanner image | Bandit source Apache-2.0; full container/transitive notices and publisher signature verification pending |
| Go, Node and Alpine image contents | Dockerfiles | Build/runtime distribution | SBOMs and licence texts produced per release; legal review pending |
| Ollama 0.34.4 | deploy/compose.ai-local.yaml (digest-pinned image) | Optional local model server, not distributed by Aegis | MIT; model weights are downloaded by the operator under their own licences |

`scripts/release/release_evidence.py` generates per-image CycloneDX SBOMs, a console npm SBOM and `THIRD_PARTY_LICENSES.txt` with the licence and NOTICE texts of every shipped Go module and production npm package (see `docs/operators/release-evidence.md`). The image contents include unmodified Alpine OS packages under GPL-2.0-only (busybox, apk-tools and others) and MPL-2.0 components (`ca-certificates`, `github.com/go-sql-driver/mysql` through Caddy's ACME server); these are listed for review in each release manifest.

No GPL/AGPL scanner is linked into Aegis core by this implementation. Standalone execution does not by itself remove redistribution obligations. Review exact component licensing and the intended distribution before release.
