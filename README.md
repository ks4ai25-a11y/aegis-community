# Aegis Community

**Self-hosted web defence you can inspect.** Aegis puts a pinned Caddy + Coraza + OWASP CRS gateway in front of your web applications, records every decision with its source, and helps you review, test and approve protection changes. It also reads your code offline to find what to fix. AI is optional, runs locally if you want it, and never controls live traffic.

> **Status: internal alpha.** Not yet for production protection. Every claim below links to its evidence; what is not done is listed in [known limitations](docs/KNOWN_LIMITATIONS.md) and the [release gates](docs/release-gates.json).

## Quickstart

```sh
scripts/quickstart.sh          # build, start, print the console URL and first-owner token
scripts/quickstart.sh --ai     # also run free local models for assessments and patch drafts
```

Open the printed loopback URL and follow [getting started](docs/user/getting-started.md). Requirements: Docker with Compose v2. Nothing requires a paid service, model or account.

## What it does

| | |
|---|---|
| **Protect your sites** | Register applications by exact host name and private origin. New sites start in **Observe**; **Protect** is enabled per site only after you review a tested policy. Per-site HTTPS (ACME or local CA), rate limits and trusted proxies. [Sites](docs/operators/sites.md) |
| **See what happened** | Sanitized telemetry (no bodies, query values, cookies or client addresses), deterministic detectors for CRS matches, enumeration, brute force, bursts, 5xx spikes, sensitive routes, policy regressions and origin exposure. Every threshold is recorded on the incident. |
| **Change safely** | Every policy change is validated by the pinned gateway, tested in an isolated fixture, explicitly approved and can be rolled back in one click. A live canary re-checks the gateway after each change. |
| **Assess incidents** | A deterministic assessment works offline; an optional local model adds schema-checked, evidence-cited hypotheses. [AI assessment](docs/operators/ai-assessment.md) |
| **Find and fix code issues** | Pinned Semgrep CE, Gitleaks, Syft, Bandit, OSV-Scanner and Trivy (with operator-provisioned offline databases) against read-only snapshots; findings with remediation steps and checked patch drafts that Aegis never applies for you. Route discovery for Next.js, Express, FastAPI and Flask; rescans when code changes. [Repositories](docs/operators/repositories.md) · [Scanner databases](docs/operators/scanner-databases.md) |
| **Plan research safely** | A research planner proposes what to test from a fixed catalogue of bundled fixture tests; it cannot run commands, contact hosts or change code. |
| **Connect your AI app** | `aegis-mcp` gives Claude, Codex or any MCP client read-only access with a revocable credential. [Assistant connections](docs/operators/assistant-connections.md) |
| **Prove it** | Signed evidence export (`aegisctl report verify`), counts-only diagnostics, measured [performance](docs/operators/performance.md), [release SBOMs and checksums](docs/operators/release-evidence.md), and an [adversarial AI evaluation](tests/ai-eval/README.md). |

## What it does not claim

A matched rule is not proof of exploitation, and a passing test is not proof an application is secure. A generic WAF does not enforce tenant ownership or stop upstream volumetric DDoS. Zero findings never means safe. See [known limitations](docs/KNOWN_LIMITATIONS.md).

## Documentation

- **Use it:** [getting started](docs/user/getting-started.md) · [operator guides](docs/operators/)
- **Understand it:** [architecture decisions](docs/architecture/adr/) · [implementation status](docs/IMPLEMENTATION_STATUS.md) · [evidence](docs/evidence/)
- **Develop it:** [local verification](docs/developers/local-verification.md) · [contributing](CONTRIBUTING.md) · [security policy](SECURITY.md)
- **Roadmap:** [Community → Frontier plan](docs/strategy/community-to-frontier.md)

## Development build

Requirements: Go 1.27.1, Node 22.23.1 and Docker Compose.

```sh
docker compose -f deploy/compose.demo.yaml build
docker compose -f deploy/compose.demo.yaml up -d
make test
```

The console is at `http://127.0.0.1:7410` and the demo gateway at `http://127.0.0.1:8080`. The controller prints a short-lived first-owner token only to its local logs.
