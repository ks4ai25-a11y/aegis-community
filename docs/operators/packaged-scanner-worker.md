# Packaged one-shot scanner worker

This opt-in profile runs one consented static scan using an enrolled operator worker. It is unfinished experimental infrastructure. It does not release cleanup admission, run arbitrary repository code, provide background recovery or establish an independent engine broker. The retained HTTP demo does not start it automatically.

## Prerequisites

Use a local Linux engine supporting API 1.55 and the platform of the pinned tool images. The worker image includes both Linux guards and a native CLI. Actual local ARM64 and disposable CI AMD64 evidence are recorded separately; these are not independent installer acceptance. Preload each selected immutable image from `tools/scanners.lock.json`. There is no image pull inside the worker. Missing OSV/Trivy advisory databases produce errors, not clean scans.

Build from the repository root:

```sh
docker build -f alpha/Dockerfile -t aegis-community/scanner-worker:0.1.0-alpha.1 .
```

Provision a new private canonical workspace on the daemon host, owned by UID/GID 10001 with mode 0700. Set `AEGIS_SCANNER_WORK_ROOT` to its absolute path. The worker mounts that directory at the **same absolute path**, allowing the daemon to resolve child source/guard mounts. Do not change ownership of an existing shared directory. Docker Desktop requires a correctly shared path; the acceptance harness exercises this reference configuration only.

Set `AEGIS_SCANNER_ASSET_ROOT` to the approved canonical provisioned repository asset directory. It must be readable by UID 10001 and match the asset names registered through the owner repository API. The packaged worker mounts it read-only at `/opt/aegis/repositories`. Queue a scan with explicit owner consent through the Scans page or owner API.

Set `AEGIS_SCANNER_ENGINE_SOCKET` to the **daemon-host** Unix socket, commonly `/var/run/docker.sock`, and `AEGIS_SCANNER_ENGINE_GID` to that socket's numeric group ID. A desktop client's host-side proxy socket is not necessarily the daemon-host bind source. The selected socket must permit the worker's UID or supplementary group access.

## Enrollment and execution

Enroll through the existing local operator command using a separate private credential volume. For the default `aegis-community` Compose project:

```sh
docker volume create aegis-community_scanner_worker_credentials
docker compose -p aegis-community -f deploy/compose.demo.yaml run --rm --no-deps \
  --volume aegis-community_scanner_worker_credentials:/run/scanner \
  --entrypoint aegisctl init scanner-worker enroll packaged-worker 60 /run/scanner/worker.credential
```

The final `60` is the credential lifetime in minutes. Set `AEGIS_SCANNER_OWNER` to the owner ID returned by enrollment. Keep the credential volume private; do not print or copy its contents into source, logs, browser storage or the controller HTTP API. Existing enrollment rules reject unsafe permissions and overwrite. See [worker operations](scanner-workers.md) for revocation and rotation.

With all five required environment variables set, inspect the resolved profile:

```sh
docker compose -p aegis-community -f deploy/compose.demo.yaml \
  -f deploy/compose.scanner-worker.yaml --profile operator-scanner config
```

Before the first worker claim, calculate the scope under the actual packaged UID and endpoint:

```sh
docker compose -p aegis-community -f deploy/compose.demo.yaml \
  -f deploy/compose.scanner-worker.yaml --profile operator-scanner \
  run --rm --no-deps scanner-worker engine-binding-input \
  "$AEGIS_SCANNER_WORK_ROOT/aegis-scanner-workspaces-10001"
```

This prints an engine digest and registry digest with authority flags false. Review and pass those exact hash strings to the local controller command:

```text
docker compose -p aegis-community -f deploy/compose.demo.yaml exec -T controller \
  aegisctl scanner-engine bind ENGINE_DIGEST REGISTRY_DIGEST
```

The initial binding requires no active or held scanner dispatch. Exact repeats return the original record. Replacement/reset is unavailable; changing a path, UID, endpoint or engine is not a cleanup workaround. Existing held installations must await trusted recovery. A restore removes prior host binding, revokes credentials and keeps cleanup held.

The profile uses `worker-once-bound`: missing binding, a changed registry or a mismatched/unavailable engine refuses before claim or source allocation. The controller also checks configured scope on reservations and launches from older clients. Scope binding does not prove independent engine mediation or cleanup. Legacy native commands in an unconfigured database retain their experimental behavior.

Leave the `engine-journal` directory absent on first initialization. An existing bare or partial directory is refused; only a complete initialized namespace with zero attempts can be reused. Initialize it under the packaged UID and selected engine, then approve its proposed root and namespace hashes:

```sh
docker compose -p aegis-community -f deploy/compose.demo.yaml \
  -f deploy/compose.scanner-worker.yaml --profile operator-scanner \
  run --rm --no-deps scanner-worker engine-journal-init \
  "$AEGIS_SCANNER_WORK_ROOT/engine-journal"
```

```text
docker compose -p aegis-community -f deploy/compose.demo.yaml exec -T controller \
  aegisctl scanner-engine bind-journal JOURNAL_ROOT_DIGEST JOURNAL_NAMESPACE_DIGEST
```

The printed initialization input is metadata with authority flags false. Review its engine digest against the first approval. Both the base engine binding and journal binding must exist before claim. Initial journal approval also refuses an active/held dispatch; existing exact repeats do not release admission. A used journal cannot be initialized/reset through this command. Keep its root path, UID and namespace stable. Never move/delete an attempted journal or select a fresh one to force another scan.

The worker refuses a substituted namespace, missing/corrupt/busy journal or unresolved lifecycle before claim. The executor checks the same approval again under the lifetime lock and never recreates missing bound state. New immutable launch documents use revision 1.2, preserving both journal hashes. The controller refuses legacy launch requests that omit this configured scope.

Run once after provisioning:

```sh
docker compose -p aegis-community -f deploy/compose.demo.yaml \
  -f deploy/compose.scanner-worker.yaml --profile operator-scanner \
  run --rm --no-deps scanner-worker
```

The worker has no Docker CLI. It uses fixed API 1.55 over a bounded Unix SDK transport, ignoring proxy and API-version overrides. Metadata preflight permits only engine info and the selected immutable image lookup; failed metadata never falls back to a CLI. Operator-native endpoint discovery can still use the Docker CLI when no explicit `DOCKER_HOST` is supplied.

The profile runs UID 10001, without network, capabilities, writable root filesystem, controller database or gateway admin channel. Its engine socket remains a powerful capability even with a read-only mount. Only a trusted operator may launch this orchestrator. Child scanner containers receive neither that socket nor enrollment credentials.

## Results and held cleanup

A tool/database failure can produce a committed `tool_error` result and a nonzero worker exit. Inspect the immutable owner result and actual tool coverage. Findings remain T0 observations. One completed suite leaves controller execution admission `cleanup_required`. A second worker must refuse the next queued job even when its local journal reports settled requests and child absence is observed.

Keep journals and workspaces after uncertain execution. Do not rotate/delete a journal, reset controller admission, select another namespace or restart repeatedly to force progress. There is no independent release or trusted reconciliation command yet. Use [journal operations](journaled-scanner-engine.md) for existing-only status inspection. Background scheduling, all-engine-write mediation, cleanup verification/release and crash recovery remain required.

The explicitly opted-in [acceptance harness](../../tests/integration/packaged_worker_acceptance.py) creates its own project, owner, credential volume and workspace, checks labels/names before resource use, executes real pinned tools, verifies the held next job and inspects removal of its own resources. It preserves uncertain fixtures rather than claiming cleanup. `AEGIS_WORKER_TEST_ALL_TOOLS=1` selects all six locally preloaded tools; the default is Bandit. This does not alter or grant release to the retained demo.
