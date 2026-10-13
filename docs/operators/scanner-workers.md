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

Enrollment is implemented; the worker transport and executor service are still unfinished. These commands alone do not start a scanner, provide Docker access to the controller or complete offline scanner orchestration. The public API has no enrollment endpoint.
