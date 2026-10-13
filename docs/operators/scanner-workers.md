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
