# Operator-launched offline scanner executor

This is an internal preview facility for Linux/macOS operators with a Linux Docker engine reachable through a local Unix socket. TCP and SSH Docker endpoints are refused. The endpoint is resolved once and bound explicitly for the entire run. It is separate from the web controller. The console does not yet schedule durable scanner jobs. Do not use it to execute application code or repository scripts; that feature remains unavailable pending a disposable VM boundary.

Build the CLI and both Linux guard architectures:

```sh
make research-build
```

Preload exact images from `tools/scanners.lock.json` using your operator-controlled image preparation process. The executor refuses to pull images. It does not provision offline OSV/Trivy databases yet; those tools return tool_error rather than a clean scan result.

A reproducible trusted-fixture invocation, from the Aegis checkout:

```sh
bin/aegis-research scan-offline semgrep_ce "$PWD/alpha/fixtures/scanners/vulnerable" "$PWD"
```

The first path must be canonical and symlink-free. The last path is your trusted Aegis installation containing its tool lock, bundled rules and built guards. The native operator process must be non-root. The container uses the same non-root UID/GID to read mode-0400 private snapshot files. No repository code, dependency installation or git hook runs. Inputs omitted by the inventory profile are explicitly outside coverage.

Supported pinned IDs are `semgrep_ce`, `gitleaks`, `syft`, `osv_v2`, `trivy` and `bandit`. Bandit 1.9.4 uses a digest-pinned upstream image, built-in tests, a fixed empty INI input and `--ignore-nosec`. Repository `.bandit` settings and inline suppression comments do not silently narrow its scope. Python syntax errors produce partial coverage diagnostics; no repository module is imported or executed. Semgrep currently uses only the bundled synthetic rule, so its coverage is deliberately narrow. Trivy's default is offline vulnerability scanning, not automatic configuration review. Syft emits a minimized package-coordinate summary. It is not a complete SBOM or an exploit proof.

The JSON execution receipt includes snapshot, tool, rules, guard, parser and invocation identities, including zero-findings and failed runs. Exit 0 means a complete or partial tool run, never that an application is secure. Exit 1 means refusal, tool_error, cancellation/deadline or unconfirmed cleanup. Check `status`, `result.diagnostics` and `cleanup_state`; missing/failed tools cannot establish zero findings. Source workspaces and containers are removed after normal completion, cancellation and timeout when cleanup is confirmed.

The guard enforces an independent container deadline even if the host CLI is killed. The supported CLI admits one scanner run per operator registry. A second invocation is refused while a live or unrecovered run occupies the registry. This includes crashed runs whose container status remains uncertain. The operator must recover that run before starting another scan. Cross-operator coordination and durable queue admission remain unfinished.

Every run creates a mode-0700 session under the current operator's canonical temporary directory, in `aegis-scanner-workspaces-UID`. Its fsynced journal binds the random container identity before launch; a kernel lease protects live runs. Unconfirmed container cleanup preserves the workspace. After a host crash, run:

```sh
bin/aegis-research recover-workspaces
```

Recovery skips leased live sessions, defers sessions younger than 180 seconds, and requires the exact journalled container to be absent on the same endpoint and engine identity. A changed or unavailable engine blocks recovery. Engine failures, malformed journals, symlinks and unknown registry entries fail closed. The command accepts no paths or container IDs and does not stop containers. Keep the same temporary-directory setting and local Docker context when recovering. Recovery is an explicit operator action; automatic durable scanner job recovery remains unfinished. Do not delete arbitrary temporary directories or other containers. No default source/AI upload or paid service is used.

Acceptance commands use only bundled trusted inert data and touch only containers created for their tests:

```sh
python3 tests/integration/snapshot_scanner_acceptance.py
python3 tests/integration/scanner_guard_acceptance.py
python3 tests/integration/bandit_acceptance.py
```

The first test requires the local QA `jsonschema` validator described by contract acceptance. These checks are not external security sign-off or a production release gate pass. ADR 016 records the remaining requirements and limits.
