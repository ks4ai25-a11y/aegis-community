# Dedicated scanner broker and private dispatch

This opt-in experimental profile separates the dispatch client from engine authority. A trusted broker runs only owner-consented static scans. Cleanup release and background scheduling/recovery remain unfinished; one completed suite still holds later jobs. This profile is separate from the earlier operator one-shot experiment and is disabled in the default demo.

## Build and provision

From the repository root, build the operator helper and two dedicated images:

```sh
docker build -f alpha/Dockerfile -t aegis-community/scanner-worker:0.1.0-alpha.1 .
docker build -f alpha/Dockerfile --target scanner-broker -t aegis-community/scanner-broker:0.1.0-alpha.1 .
docker build -f alpha/Dockerfile --target scanner-dispatch -t aegis-community/scanner-dispatch:0.1.0-alpha.1 .
```

Connect an owned read-only repository first. Use the canonical daemon-host workspace, approved assets and socket setup from [packaged scanner operations](packaged-scanner-worker.md). Set `AEGIS_SCANNER_WORK_ROOT`, `AEGIS_SCANNER_ASSET_ROOT`, `AEGIS_SCANNER_ENGINE_SOCKET`, `AEGIS_SCANNER_ENGINE_GID` and, after enrollment below returns it, the owner ID in `AEGIS_SCANNER_OWNER`. Provision the workspace as UID/GID 10001, mode 0700, mirrored at the same absolute host/container path. Preload the exact selected scanner pins; missing advisory databases remain errors.

Choose `AEGIS_SCANNER_BROKER_ID` as a new enrollment ID, such as `local-scanner-broker`. Create two different private capabilities:

```sh
docker volume create aegis-community_scanner_broker_worker_credentials
docker volume create aegis-community_scanner_broker_client_credentials
docker compose -p aegis-community -f deploy/compose.demo.yaml run --rm --no-deps \
  --volume aegis-community_scanner_broker_worker_credentials:/run/scanner \
  --entrypoint aegisctl init scanner-worker enroll "$AEGIS_SCANNER_BROKER_ID" 60 /run/scanner/worker.credential

docker run --rm --pull=never --network none --read-only --user 10001:10001 \
  --cap-drop ALL --security-opt no-new-privileges \
  --mount type=volume,src=aegis-community_scanner_broker_client_credentials,dst=/run/dispatch-credential \
  aegis-community/scanner-dispatch:0.1.0-alpha.1 enroll /run/dispatch-credential/client.credential
```

Enrollment returns owner identity and expiry without printing the worker token. The dispatch enrollment prints no token either. Keep both volumes private. Never copy the worker capability into the dispatch credential; the broker refuses role aliasing. Existing credential files are refused rather than overwritten.

Use a trusted operator helper to calculate engine/registry input and initialize a new journal. It has engine authority and is not the limited dispatch client:

```sh
aegis_broker_provision() {
  docker run --rm --pull=never --network none --read-only --user 10001:10001 \
    --group-add "$AEGIS_SCANNER_ENGINE_GID" --cap-drop ALL --security-opt no-new-privileges \
    --env DOCKER_HOST=unix:///run/engine/docker.sock --env DOCKER_CONTEXT= \
    --mount "type=bind,src=$AEGIS_SCANNER_WORK_ROOT,dst=$AEGIS_SCANNER_WORK_ROOT" \
    --mount "type=bind,src=$AEGIS_SCANNER_ENGINE_SOCKET,dst=/run/engine/docker.sock,readonly" \
    aegis-community/scanner-worker:0.1.0-alpha.1 "$@"
}
aegis_broker_provision engine-binding-input "$AEGIS_SCANNER_WORK_ROOT/aegis-scanner-workspaces-10001"
aegis_broker_provision engine-journal-init "$AEGIS_SCANNER_WORK_ROOT/engine-journal"
```

Leave the journal path absent initially. Existing partial or attempted state is refused without repair/reset. Review the returned hashes and approve the complete chain locally:

```text
docker compose -p aegis-community -f deploy/compose.demo.yaml exec -T controller aegisctl scanner-engine bind ENGINE_DIGEST REGISTRY_DIGEST
docker compose -p aegis-community -f deploy/compose.demo.yaml exec -T controller aegisctl scanner-engine bind-journal JOURNAL_ROOT_DIGEST JOURNAL_NAMESPACE_DIGEST
```

```sh
docker compose -p aegis-community -f deploy/compose.demo.yaml exec -T controller \
  aegisctl scanner-engine bind-broker "$AEGIS_SCANNER_BROKER_ID"
```

Initial approvals require no active/held dispatch. They are immutable and bound to the existing owner/engine/registry/journal; exact replay is metadata only. Do not delete state, rotate a namespace or replace an enrollment to bypass a hold. Binding replacement and trusted recovery are not implemented.

## Run and withdraw

Inspect the resolved profile, start only the broker, then explicitly dispatch one consented queued job:

```sh
docker compose -p aegis-community -f deploy/compose.demo.yaml -f deploy/compose.scanner-broker.yaml --profile operator-broker config
docker compose -p aegis-community -f deploy/compose.demo.yaml -f deploy/compose.scanner-broker.yaml --profile operator-broker up -d --no-deps scanner-broker
docker compose -p aegis-community -f deploy/compose.demo.yaml -f deploy/compose.scanner-broker.yaml --profile operator-broker run --rm --no-deps scanner-dispatch
```

A listening socket does not prove enrollment/scope is available. The limited client returns state and digests, not findings or secrets. Read the source-bound result through the owner Scans/Findings pages. A committed `tool_error` returns a nonzero client exit; missing databases and partial coverage must not be treated as clean. A later job remains queued behind `cleanup_required`, even when local journal requests are settled.

The dispatch client mounts only its credential and broker socket, both read-only, with no daemon group. The broker retains powerful daemon access despite a read-only socket mount. No claim of independent all-write mediation, hostile-code VM isolation or cleanup release is made.

Stop only this broker with `docker compose -p aegis-community -f deploy/compose.demo.yaml -f deploy/compose.scanner-broker.yaml --profile operator-broker stop scanner-broker`. The profile grants a 25-second shutdown window so cancelled work can join. Keep uncertain journals/workspaces. To withdraw further dispatch, remove the dispatch credential through the trusted operator path; to revoke worker authority, use `aegisctl scanner-worker revoke BROKER_ID`. Withdrawal does not certify termination or cleanup. Existing runs remain subject to their original owner/controller/guard deadlines. Expired/revoked broker enrollment requires future approved recovery/replacement; do not reuse an ID or edit binding records.
