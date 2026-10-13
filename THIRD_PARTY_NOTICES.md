# Third-party component inventory

Aegis-authored source is Apache-2.0. This file is an inventory under review, not a completed legal approval or substitute for upstream licence/notice text. Container distributions include additional OS and transitive dependencies; their complete notices and SBOMs must be produced before publication.

| Component | Pinned source | Distribution/use | Review state |
|---|---|---|---|
| Caddy | gateway/go.mod and go.sum, v2.11.4 | Gateway binary | Transitive notices pending |
| coraza-caddy | gateway/go.mod and go.sum, v2.6.2 | Linked gateway module | Transitive notices pending |
| Coraza / OWASP CRS | gateway/go.sum, v3.8.1 / v4.25.0 | Engine / embedded rules | Notice extraction pending |
| modernc SQLite, crypto and UUID | controller/go.mod and go.sum | Controller binary | Notices pending |
| React, Vite, TypeScript, Lucide | console/package-lock.json | Browser assets / build tools | Notices pending |
| Semgrep CE | tools/scanners.lock.json | Optional standalone scanner image | CLI/engine licence separation requires review |
| OSV Scanner V2, Trivy, Syft, Gitleaks | tools/scanners.lock.json | Optional standalone scanner images | Licences, notices and publisher signature review pending |
| Go, Node and Alpine image contents | Dockerfiles | Build/runtime distribution | SBOM and notices pending |

No GPL/AGPL scanner is linked into Aegis core by this implementation. Standalone execution does not by itself remove redistribution obligations. Review exact component licensing and the intended distribution before release.
