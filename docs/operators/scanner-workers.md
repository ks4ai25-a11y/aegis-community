# Local scanner worker enrollment

Connect the provisioned read-only repository as its owner first. On the trusted controller host, use the local CLI with a new private credential filename:

```sh
aegisctl scanner-worker enroll local-offline-worker 60 /var/lib/aegis/offline-worker.token
```

The lifetime is in minutes, from one to 1440. The command prints worker/owner identity and expiry, and writes the capability only to the new mode-0600 file. Existing files are refused. Keep that file private; worker transport will read it directly rather than receiving credentials through argv or browser requests. A new enrollment ID is required after expiry/revocation; identity replacement is deliberate rather than automatic.

Withdraw the role with:

```sh
aegisctl scanner-worker revoke local-offline-worker
```

Revocation requests cancellation of a running job and prevents future claim/renewal. It does not confirm external container termination or release uncertain cleanup admission. Delete your revoked credential file according to local credential-retention policy.

In the current demo, run these commands via `docker compose -f deploy/compose.demo.yaml exec -T controller aegisctl ...` with the credential path inside its protected controller volume. Update all shared-image services using the local demo upgrade guide before invoking a newer binary against migrated state.

Enrollment and the private Unix channel are implemented; the actual executor worker is still unfinished. These commands alone do not start a scanner, provide Docker access to the controller or complete offline scanner orchestration. The public API has no enrollment endpoint.

The Unix worker channel is now implemented. Check enrolled identity from the trusted controller host:

```sh
aegisctl scanner-worker probe /var/lib/aegis/offline-worker.token
```

Set AEGIS_SCANNER_SOCKET to the owned private listener. The demo sets /run/scanner/worker.sock and mounts its private volume only in the controller. Browser cookies and the public dashboard port do not provide this channel. Probe reads the private credential directly and prints only enrollment metadata. Revocation makes subsequent probes fail. Linux/macOS private sockets are implemented; Windows IPC and remote worker transport are not.

The finite private protocol uses POST /internal/v1/scanner/identity and /claim with {}, and /guard and /fail with job_id, request_digest and lease_token; /fail additionally requires a finite error_code. The server derives owner/worker identity from Bearer authentication. Only a private claim response delivers the distinct lease capability. No arbitrary path, command, network target or boolean cleanup acknowledgement is accepted. This is not a public API contract or a completed scanner service: the actual executor worker and result/cleanup ingestion still remain required.

## Scanner-side client foundation

`alpha/workerchannel.New(socket, credentialFile, expectedOwner, trustedLockDigest)` constructs the scanner-side client on Linux/macOS. `Identity`, `Claim`, `Guard` and `Fail` use only the dedicated Unix channel. `Claim` distinguishes an empty queue with `ErrEmpty` and refuses mismatched request/map/pin/owner identities. `Fail` acknowledges a terminal tool error with cleanup admission still occupied. `Close` closes idle transport connections; it does not cancel jobs or assert cleanup.

This package is not yet a runnable worker service. No scanner tool is launched, no receipt is ingested and no cleanup slot is released by calling these methods. Operator enrollment and probe commands remain the available deployed CLI operations. See ADR 025 for the validation boundary and remaining integration work.

`Client.RunWithLease` renews a claimed lease every five seconds and cancels a cooperative task on authority/channel failure or the original deadline. It checks authority before task start and after a successful task return, waits for task cleanup and joins its renewal loop. It does not stop arbitrary code by itself, complete a scanner job or release dispatch admission. A worker executor must honor the context and independently confirm process/workspace cleanup. Actual client/controller interoperability is covered by `make test` through the test-only `tests/integration/scannerchannel` module; the runnable worker service and receipt boundary remain unfinished.

The shared `aegis.local/source/scanevidence` contract now provides `Decode` and `Normalize` for receipt validation against trusted job, map, requested-tool and pin context. It has no execution or state-writing capability. Worker cleanup fields remain claims; they do not release admission. OSV/Trivy receipts with unproven database freshness normalize to `completed_stale_db`. The private receipt-ingest operation is implemented through ADR 029; the runnable scanner worker service remains unfinished. See ADR 027.

The controller has an internal immutable receipt ledger (`Queue.RecordReceipt` / `Queue.Receipts`) with migration 7. Receipts are owner/job/tool scoped, normalized against trusted startup pins and committed with their audit event. Receipt acceptance does not complete jobs or release cleanup admission. The ledger caps storage at 64 MiB/6,000 records; archive rotation remains unfinished; private transport ingest is implemented through ADR 029. Upgrade all services sharing the controller image after initializing the new schema, following the local-demo upgrade guide. See ADR 028.

## Private receipt submission

`POST /internal/v1/scanner/receipt` is available only on the dedicated Unix listener with an active worker Bearer credential. The canonical JSON envelope requires `schema_version`, `job_id`, `request_digest`, `lease_token` and `execution`; the owner comes from enrollment. The envelope is limited to 8 MiB + 4 KiB and execution to 8 MiB. Cookies, Origin, query parameters, content encoding and unknown/case-alias fields are refused.

`Client.SubmitReceipt(ctx, lease, execution)` normalizes before upload and verifies the exact immutable document digest in the acknowledgement. An accepted receipt still reports `cleanup_required: true` and does not complete the job. Exact committed replay is safe after deadline expiry; new expired writes are denied by the controller. The one-shot execution path is described below; cleanup release and terminal suite operations remain unfinished. See ADR 029.


## One-shot static worker

Build with `make research-build`. On a Linux/macOS operator host with access to the enrolled private socket, credential file and local Docker engine:

```sh
bin/aegis-research worker-once SOCKET CREDENTIAL_FILE OWNER CANONICAL_AEGIS_SOURCE_ROOT CANONICAL_ASSET_ROOT
```

Pass the credential file path, never its contents. The asset root is the provisioned parent containing registered asset directories. The source root contains the trusted scanner lock, local rules and built guards. Paths must be absolute and canonical. No image pull, repository hook or dependency installation is performed.

One job is claimed. Each scanner receives a separately journaled snapshot checked against the approved map, with live authority checks before launch. Uncertain cleanup preserves its workspace and stops execution. Exact receipt acknowledgements are printed as bounded metadata; raw scanner output and capabilities are omitted.

Exit zero with `no_job` means nothing was claimed. The command now prints a durable terminal result: `completed`, `completed_partial`, `completed_stale_db` or `tool_error`. A tool error exits nonzero. These are static scanner statuses; no complete coverage or clean-application conclusion follows. Admission remains occupied for independent cleanup verification. This command cannot make it reusable. Independently verified cleanup release remains required.

Native acceptance uses an actual controller under the operator UID. The Compose demo socket is owned by UID 10001; this command does not establish workstation access to it. Do not loosen socket permissions to bridge that deployment gap. A background worker service and deployable worker/controller pairing remain unfinished. See ADR 030.


## Terminal result derivation

`POST /internal/v1/scanner/finish` accepts only the original job/request/lease binding. The controller requires every requested immutable tool receipt and derives terminal state, independent partial/stale/error flags, per-tool claim counts and receipt references. It commits the result, job transition and audit together, then retains `cleanup_required` admission. No worker-supplied status or cleanup boolean is accepted. Exact committed replay can succeed after deadline expiry with active enrollment; it cannot authorize new execution.

`Client.Finish` checks the full bounded result digest, original identities and accepted receipt references. The result's `finding_claims` counts tool claims, which can overlap. All evidence remains T0. A channel failure after receipt submission reports `finalization_unconfirmed`; it does not establish whether the result committed. Background recovery and operator resume interfaces remain unfinished.

Migration 8 adds an immutable result ledger. Follow the local-demo upgrade guide: protected online backup, build/initialize the shared image, verify zero init exit, then recreate deployer/verifier/controller together. The owner-scoped internal result accessor is implemented; public scanner result routes and GUI are still pending. See ADR 031 and the generated `ScannerSuiteV1` / `ScannerSuiteResultV1` contracts.


## Prelaunch intent registration

Before Docker receives a fixed scanner run, the native worker now fsyncs its local journal and calls `POST /internal/v1/scanner/launch`. The canonical envelope contains `schema_version`, original `job_id` / `request_digest` / `lease_token`, and a `plan` with tool ID, Aegis container name, engine digest, workspace ID, registry digest and approved snapshot digest. It contains no filesystem path or cleanup assertion. The envelope is bounded to 8 KiB and must use canonical keys, including nested plan keys.

The controller commits an immutable attempt and audit together, derives the trusted pin/profile/deadline, and refuses changed attempts or a second engine/registry in one suite. The client verifies the exact acknowledgement against its prepared local execution. An executed receipt must match that attempt; container-free preflight output cannot erase an already recorded launch.

Claims require `launch_protocol: "1.0"`. Migration 9 preserves old dispatches with protocol zero and no invented records; they remain occupied and cannot renew new execution. Exact launch replay requires current authority, including after a prior commit. Update all services sharing the controller image using the backup/initializer procedure before using the new worker.

Launch records support later independent verification; they never release admission. A capture/workspace crash before the first record remains uncertain, and zero records do not prove cleanup. Trusted namespace/capture registration and an independent verifier are still required. See ADR 032 and `ScannerLaunchPlanV1`, `ScannerLaunchV1`, `ScannerLaunchRecordV1`.

## Workspace reservations before source capture

The native worker now requires `workspace_protocol: "1.0"` as well as the launch protocol. It reserves each selected tool's opaque run ID through the private channel while holding local registry admission, before creating that run directory or copying source. Its private journal stores the acknowledged reservation digest. Launches must match that earlier workspace/registry/snapshot reservation. Lost acknowledgements can leave committed reservations without allocated runs; admission remains occupied.

Migration 10 preserves legacy dispatches with workspace protocol zero and no fabricated history. Follow the protected backup/shared-image initializer procedure. A malformed incomplete allocation still requires trusted recovery; do not delete controller admission rows or treat no launches as cleanup proof. Independent registry/engine verification and cleanup release remain unfinished. See ADR 033 and `ScannerWorkspacePlanV1`, `ScannerWorkspaceV1` and `ScannerWorkspaceRecordV1` contracts.

## Original deadline inside the guard

Rebuild the native CLI and both Linux guards with `make research-build`. The fixed worker passes the original job deadline to PID 1; delayed starts refuse before source reads or scanner creation, and valid runs use the smaller remaining deadline/tool budget. The updated guard refuses older invocations without an absolute deadline. Its changed binary digest is recorded in execution receipts. Standalone offline scans derive a finite local deadline.

This improves late-start control but does not release cleanup admission or attest historical guard provenance. Independent verification must still account for queued requests, containers and trusted workspaces. See ADR 034.

## Provisioned guard build sets

The controller's private scanner channel now loads the two fixed packaged guard files from `/opt/aegis/guards` (or an explicit canonical operator configuration) and binds their actual hashes to fresh dispatches. Rebuild native guards with `make research-build`; both native and Docker guard builds disable VCS metadata to support identical hashes. A worker guard outside the acknowledged set, a changed set during a lease or a receipt naming another guard is refused.

Migration 11 retains historical dispatches with an empty guard-set binding, preserving their records/admission while refusing new execution. Use the protected backup/shared-image initializer upgrade procedure. V1 launch records remain historical; V2 contracts describe schema 1.1 guard-bound records. This provides trusted local package identity, not signatures, runtime attestation or cleanup release. See ADR 035.

## Owner scan API

The local owner session API now supports `POST /api/v1/scans` with a valid CSRF token and `Idempotency-Key`. The strict body uses `schema_version: "1.0"`, `app_id: "app_demo"`, the owned `repository_id` and current `map_digest`, `mode: "repo_offline"`, sorted unique `tool_ids`, and `tool_timeout_seconds` from 1 to 120. Connect a provisioned repository through `/repos` first. Arbitrary paths/URLs, images, commands, owner IDs and worker capabilities are not request fields. See the generated `createScan` client and ScannerJobInputV1 contract.

`GET /scans` lists at most 100 owned jobs. `GET /scans/{id}` returns job and `execution_admission`; `POST /scans/{id}/cancel` accepts `{}`. Cancellation requests cooperative stop and never confirms container/workspace absence. `GET /scans/{id}/result` returns the immutable digest-checked suite index or HTTP 409 `RESULT_NOT_READY`. An absent/unowned job returns 404. Standalone Go/Python clients bound responses to 128 KiB. The public API does not enroll workers, renew leases, authorize launches or release admission.

An unprovisioned scanner service returns 503. A queued request is not evidence that a background worker is deployed or that a scanner ran. An active dispatch remains `active`, terminal execution awaiting independent cleanup reports `cleanup_required`, and a cancelled job without a dispatch reports `unconfirmed`. A T0 result is a static tool claim, not a reproduced exploit or a clean-application assurance. Run `python3 tests/integration/scanner_owner_api_acceptance.py` only against the named trusted local demo; it queues and cancels a job without executing repository code. ADR 036 records the remaining boundaries.

## Scans console

Open **Scans** in the local console after connecting a provisioned repository. Select the repository map, supported tools and a 1–120 second tool budget, then authorize read-only scanning. OSV/Trivy require separately provisioned offline databases. Queueing does not install a worker or run repository code. An unchanged retry after an unconfirmed acknowledgement reuses its idempotency key; a changed request uses a new key.

Select a retained job to read its execution admission and cancellation state. The selected queued/running job polls every two seconds. Terminal suite summaries retain T0 tool claims, independent partial/stale/error flags and cleanup holds; missing/mismatched results are not rendered as clean scans. **Cancel selected scan** requests cooperative stop without releasing admission. Individual findings detail and a reusable background worker remain unfinished. See ADR 037.

`cd console && npm run test:browser` runs isolated contract-fixture browser checks, after installing the browser with `npx playwright install chromium`. The explicitly enabled live check (`AEGIS_LIVE_UI_TEST=1`) is only for the named trusted local demo with its protected test credential; tracing is disabled and it queues/cancels one safe-repository request without executing it. Browser fixtures alone do not establish real scanner execution, independent installation or security sign-off.
