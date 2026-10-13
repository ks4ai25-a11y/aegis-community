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
