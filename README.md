# Aegis Community

Implementation in progress against the **OSS-first Engineering Master Manual v4**. Aegis combines a local Caddy/Coraza/CRS defence gateway with a separate authorized application research and verification plane. AI remains optional and never controls live traffic directly.

The current source is an unfinished internal alpha. See [implementation status](docs/IMPLEMENTATION_STATUS.md). Do not deploy it as production protection or assume research/scanner capabilities are available yet.

## Development build

Requirements: Go 1.27.1, Node 22.23.1 and Docker Compose.

```sh
docker compose -f deploy/compose.demo.yaml build
docker compose -f deploy/compose.demo.yaml up -d
```

The loopback console is intended at `http://127.0.0.1:7410`; the synthetic gateway at `http://127.0.0.1:8080`. Local ARM64 Docker Desktop acceptance covers Observe/Protect, expected CRS 942100, privacy, activation retry, rollback, controller loss and gateway restart; see `docs/evidence/demo-acceptance.json`. Broader release gates remain pending. The controller prints a short-lived first-owner token only to local logs. Start in Observe; Protect requires explicit owner approval of a tested exact policy revision.

The synthetic fixture contains no customer data. WAF request-level denial does not establish that application vulnerabilities are fixed. A generic HTTP WAF does not enforce tenant ownership or prevent upstream volumetric DDoS.

No hidden telemetry, paid model, proprietary component or vendor account is required. Public release additionally requires signed artifacts, notices, measured tests and independent review.


## Local verification

Run module tests from each of `gateway`, `controller`, `alpha`, `shared/source` and `contracts` using `go test -race ./...`; build the console with `npm ci` and `npm run build` in `console`. Run `python3 tests/integration/demo_acceptance.py` against a dedicated demo installation in Observe mode. It temporarily activates Protect, stops the demo controller, restarts the demo gateway and restores Observe. The script creates a demo owner on first use and stores its random passphrase locally with mode 0600 at `/private/tmp/aegis-demo-test-credential`, not in source or reports. Do not use it against an existing user installation.

`tools/scanners.lock.json` pins optional scanner images. `tests/integration/scanner_acceptance.py` runs their read-only static fixture checks with no network or Docker socket. It requires the images to be pulled separately and the `bin/aegis-research` CLI to be built from `alpha`. Semgrep CE, Gitleaks and Syft have local fixture evidence. OSV V2 and Trivy need approved offline database provisioning before known-advisory results are available; missing databases are explicit tool errors.

`python3 scripts/generate_contracts.py` regenerates the current Draft 2020-12 schemas and Go/TypeScript/Python bindings. `python3 scripts/generate_research_api.py` generates scoped Go/Python/TypeScript REST clients from `contracts/openapi-research.json`; the console uses that client. The complete catalogue and remaining API clients are still in development.


The Verify page supports exact scope review, approval, durable fixture jobs, cancellation, revocation and owned report history. `python3 tests/integration/scoped_jobs_acceptance.py` tests these against the named local demo services and kills/restarts only the Aegis controller to check lease recovery. It uses the synthetic demo owner credential created by the earlier acceptance script. Scope grants are fixed to the bundled test_lab and allow four requests total; arbitrary staging targets remain unavailable.

`make test` verifies generated-file reproducibility, module race tests and the console build. CI workflow source is pinned to upstream action commits; an actual hosted CI run and independent installation remain release gates.

The **Repositories** page connects provisioned read-only assets and shows conservative application maps using generated clients. The demo provides `safe` and `vulnerable` static scanner fixtures. See [repository operations](docs/operators/repositories.md). The owner API can now enqueue/list offline scans, read status, cancel jobs and read immutable T0 suite results through `/api/v1/scans`; see [scanner operations](docs/operators/scanner-workers.md). The **Scans** page now provides repository/tool consent, job history, cancellation and immutable T0 suite summaries. Selected immutable scans now show normalized finding details with filters, conservative dependency deduplication and original source/receipt identities. Global finding history/triage, background worker deployment and independent cleanup verification/release remain unfinished. A queued job does not mean a worker is available, and a terminal result does not prove resource cleanup.

An operator-only `scan-offline` CLI captures exact private source snapshots and runs pinned tools behind an independent container deadline/output guard. See [offline scanner operations](docs/operators/offline-scanners.md). It adds no Docker socket to the web controller; durable scanner orchestration, host crash workspace recovery and offline advisory databases remain incomplete.
